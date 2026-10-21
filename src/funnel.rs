//! The inbound route: Tailscale Funnel with raw TCP passthrough to Caddy (owner decision of 2026-10-07). A stop
//! of Caddy does not close another handler of tailscaled, for example a Funnel handler straight to the model
//! server, so grant refuses and reconcile notifies while the serve config is not the one handler of the
//! procedure in install.sh (TODOS.md, "Check the Funnel setup in reconcile and install.sh").

use crate::config;
use crate::runner::{Runner, run_ok};
use serde_json::{Value, json};
use std::net::SocketAddr;

/// The serve config of tailscaled, as `tailscale serve status --json` prints it (a local call, no network).
pub fn serve_config(runner: &dyn Runner) -> Result<Value, String> {
    let out = run_ok(runner, &["tailscale", "serve", "status", "--json"])
        .map_err(|e| format!("cannot read the serve config of tailscaled: {e}"))?;
    serde_json::from_str(&out.stdout)
        .map_err(|e| format!("cannot read the serve config of tailscaled: `tailscale serve status --json` gave no JSON: {e}"))
}

/// The error for a serve config that is not exactly the one handler of `tailscale funnel --bg --tcp=443
/// tcp://127.0.0.1:443`: TCP 443 to Caddy on 127.0.0.1:443, with Funnel on only for the host of PUBLIC_URL on
/// port 443. tailscaled leaves out each empty field (`omitempty` in ipn.ServeConfig), so each other handler (a
/// Web handler, another TCP port, a service, a foreground `tailscale serve`) or a Funnel for another name or
/// port makes the JSON differ.
pub fn mismatch(serve: &Value, public_url: &str) -> Option<String> {
    let host = config::host(public_url);
    // The port of PUBLIC_URL, if it has one: the text between the host and the path. Funnel and Caddy use 443.
    let port = public_url["https://".len() + host.len()..].split(['/', '?', '#']).next().unwrap_or("");
    // A number, as curl reads it: an empty port is 443 and ":0443" is 443; a port out of range never matches.
    let port = match port.trim_start_matches(':') {
        "" => 443,
        digits => digits.parse::<u16>().unwrap_or(0),
    };
    // The Funnel name has no user part ("u:PASSWORD@"), so the error text also holds no password.
    let name = host.rsplit_once('@').map_or(host, |(_, name)| name);
    // tailscaled writes the DNS name in lower case; Caddy and TLS compare names with no regard to case.
    let site = format!("{}:{port}", name.to_ascii_lowercase());
    let mut expected = json!({"TCP": {"443": {"TCPForward": "127.0.0.1:443"}}, "AllowFunnel": {}});
    expected["AllowFunnel"][&site] = json!(true);
    (*serve != expected).then(|| {
        let serve = shown(serve);
        format!(
            "the serve config of tailscaled is {serve}, and it must be exactly {expected}: a stop of the gateway does not close another handler of tailscaled, for example one straight to the model server; see `tailscale serve status --json` and `tailscale funnel status`, then `tailscale funnel reset` and `tailscale funnel --bg --tcp=443 tcp://127.0.0.1:443`"
        )
    })
}

/// The serve config for an error text: each string value is "…", except a TCP forward address that is an IP
/// address and a port (127.0.0.1:8000, [::1]:8000). A proxy URL, a redirect, a text handler or a raw
/// `tailscale serve set-raw` value can hold a password, and the error text goes to the journal and to NOTIFY_URL;
/// the keys (ports, names, paths) and the forward targets show which handler is wrong.
fn shown(value: &Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, field)| {
                    let field = match field.as_str() {
                        Some(address) if key == "TCPForward" && address.parse::<SocketAddr>().is_ok() => field.clone(),
                        _ => shown(field),
                    };
                    (key.clone(), field)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(shown).collect()),
        Value::String(_) => json!("…"),
        _ => value.clone(),
    }
}

/// The cause of a serve config that does not match, when tailscaled does not run yet: tailscaled reads the serve
/// config of its profile only with its first netmap, and before it `tailscale serve status --json` prints `{}`
/// (spark-3, the boot after the power cut of 2026-10-21: the boot run of reconcile came 4 s before the state Running,
/// and sent a false notification). In each state other than Running, Funnel serves nothing. None: tailscaled runs,
/// or its state cannot be read; then the mismatch counts.
pub fn not_running(runner: &dyn Runner) -> Option<String> {
    // The JSON form prints the state in each state (`--peers=false`: no list of the other nodes).
    let out = runner.run(&["tailscale", "status", "--json", "--peers=false"]).ok()?;
    let status: Value = serde_json::from_str(&out.stdout).ok()?;
    match status["BackendState"].as_str()? {
        "Running" => None,
        state => Some(format!(
            "tailscaled does not run yet (BackendState {state:?}); it reads its serve config with its first netmap, and Funnel serves nothing before that"
        )),
    }
}

/// Grant step 1: the serve config is the one handler of the inbound route. A grant during the start of tailscaled
/// refuses too, with that cause.
pub fn check(runner: &dyn Runner, public_url: &str) -> Result<(), String> {
    let Some(error) = mismatch(&serve_config(runner)?, public_url) else {
        return Ok(());
    };
    Err(not_running(runner).map_or(error, |cause| format!("{cause}; run grant again when `tailscale status` shows that it runs")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::{FakeRunner, output};

    const URL: &str = "https://spark.example.net";
    /// The output of `tailscale serve status --json` after the procedure of install.sh (json.MarshalIndent).
    const PROCEDURE: &str = "{\n  \"TCP\": {\n    \"443\": {\n      \"TCPForward\": \"127.0.0.1:443\"\n    }\n  },\n  \"AllowFunnel\": {\n    \"spark.example.net:443\": true\n  }\n}\n";

    // Value: protects=grant refuses and reconcile notifies for each serve config other than the one handler to
    // Caddy, because a stop of Caddy does not close another handler; fails_when=the comparison ignores a field,
    // a port, the Funnel name, or the forward address; why_new=no check of the serve config existed; seam=none
    #[test]
    fn only_the_one_handler_of_the_procedure_matches() {
        let serve = |text: &str| serde_json::from_str::<Value>(text).unwrap();
        assert_eq!(mismatch(&serve(PROCEDURE), URL), None);
        // The name of PUBLIC_URL in other letter case, and with an explicit port 443.
        assert_eq!(mismatch(&serve(PROCEDURE), "https://Spark.Example.NET"), None);
        assert_eq!(mismatch(&serve(PROCEDURE), "https://spark.example.net:443"), None);
        // A user part is not the Funnel name, and its password stays out of the error (/ship review, F1).
        assert_eq!(mismatch(&serve(PROCEDURE), "https://u:PASSWORD@spark.example.net"), None);
        assert!(!mismatch(&serve("{}"), "https://u:PASSWORD@spark.example.net").unwrap().contains("PASSWORD"));
        let tcp = r#""TCP":{"443":{"TCPForward":"127.0.0.1:443"}}"#;
        let funnel = r#""AllowFunnel":{"spark.example.net:443":true}"#;
        for other in [
            "null".to_string(),
            "{}".to_string(),
            // Funnel off, or no handler.
            format!("{{{tcp}}}"),
            format!("{{{funnel}}}"),
            // A second handler: TCP 8443 straight to the model server, with Funnel on for it.
            r#"{"TCP":{"443":{"TCPForward":"127.0.0.1:443"},"8443":{"TCPForward":"127.0.0.1:8000"}},"AllowFunnel":{"spark.example.net:443":true,"spark.example.net:8443":true}}"#.to_string(),
            // A second handler on the tailnet only (no Funnel).
            format!(r#"{{"TCP":{{"443":{{"TCPForward":"127.0.0.1:443"}},"8000":{{"TCPForward":"127.0.0.1:8000"}}}},{funnel}}}"#),
            // HTTPS mode: tailscaled ends TLS and proxies to the model server.
            format!(r#"{{"TCP":{{"443":{{"HTTPS":true}}}},"Web":{{"spark.example.net:443":{{"Handlers":{{"/":{{"Proxy":"http://127.0.0.1:8000"}}}}}}}},{funnel}}}"#),
            // The right handler, but a foreground `tailscale serve` adds one more.
            format!(r#"{{{tcp},{funnel},"Foreground":{{"abc":{{"TCP":{{"10000":{{"TCPForward":"127.0.0.1:8000"}}}}}}}}}}"#),
            format!(r#"{{{tcp},{funnel},"Services":{{"svc:model":{{"TCP":{{"443":{{"TCPForward":"127.0.0.1:8000"}}}}}}}}}}"#),
            // Another forward address, TLS ended by tailscaled, a PROXY protocol header.
            format!(r#"{{"TCP":{{"443":{{"TCPForward":"localhost:443"}}}},{funnel}}}"#),
            format!(r#"{{"TCP":{{"443":{{"TCPForward":"127.0.0.1:443","TerminateTLS":"spark.example.net"}}}},{funnel}}}"#),
            format!(r#"{{"TCP":{{"443":{{"TCPForward":"127.0.0.1:443","ProxyProtocol":1}}}},{funnel}}}"#),
            // Funnel for another name, a second name, or a false entry.
            format!(r#"{{{tcp},"AllowFunnel":{{"other.example.net:443":true}}}}"#),
            format!(r#"{{{tcp},"AllowFunnel":{{"spark.example.net:443":true,"other.example.net:443":true}}}}"#),
            format!(r#"{{{tcp},"AllowFunnel":{{"spark.example.net:443":false}}}}"#),
        ] {
            let error = mismatch(&serve(&other), URL);
            assert!(error.as_ref().is_some_and(|e| e.contains("tailscale funnel status")), "{other}: {error:?}");
        }
        // A PUBLIC_URL with another port: Caddy and Funnel use 443 only.
        assert!(mismatch(&serve(PROCEDURE), "https://spark.example.net:8443").is_some());
        // curl reads ":0443" and an empty port as 443, so the setup of the procedure matches them too (Codex, land).
        assert_eq!(mismatch(&serve(PROCEDURE), "https://spark.example.net:0443"), None);
        assert_eq!(mismatch(&serve(PROCEDURE), "https://spark.example.net:"), None);
        assert!(mismatch(&serve(PROCEDURE), "https://spark.example.net:99999").is_some());
    }

    // Added for the Codex review of the land (2026-10-13).
    // Value: protects=a password in a proxy URL, a redirect, a text handler or a raw TCP forward value of another
    // handler stays out of the error text, which goes to the grant output, the journal and the NOTIFY_URL message;
    // fails_when=the error prints a string value of the serve config other than a TCP forward to an IP and a port;
    // why_new=only the user part of PUBLIC_URL was kept out; seam=none
    #[test]
    fn error_text_holds_no_secret_of_a_handler() {
        let serve = serde_json::from_str::<Value>(
            r#"{"TCP":{"443":{"TCPForward":"127.0.0.1:443"},"8443":{"HTTPS":true},"10000":{"TCPForward":"127.0.0.1:8000"},"8444":{"TCPForward":"tcp://u:SECRET@127.0.0.1:8000"},"8445":{"TCPForward":"[::1]:8000"},"8446":{"TCPForward":"admin:SECRET-staple"}},"Web":{"spark.example.net:8443":{"Handlers":{"/":{"Proxy":"http://u:SECRET@127.0.0.1:8000/v1"},"/r":{"Redirect":"301://u:SECRET@127.0.0.1:8000/v1"},"/s":{"Redirect":"//u:SECRET@127.0.0.1:8000/v1"},"/t":{"Text":"key SECRET, see https://docs.example.net"}}}},"AllowFunnel":{"spark.example.net:443":true,"spark.example.net:8443":true}}"#,
        )
        .unwrap();
        let error = mismatch(&serve, URL).unwrap();
        assert!(!error.contains("SECRET") && !error.contains("u:") && !error.contains("docs.example.net"), "{error}");
        // The keys and the plain forward targets stay, so the owner can see which handler is wrong.
        assert!(error.contains(r#""10000":{"TCPForward":"127.0.0.1:8000"}"#) && error.contains(r#""8445":{"TCPForward":"[::1]:8000"}"#), "{error}");
        assert!(error.contains(r#""8444":{"TCPForward":"…"}"#) && error.contains(r#""/r":{"Redirect":"…"}"#), "{error}");
        assert!(error.contains(r#""spark.example.net:8443":true"#) && error.contains("`tailscale serve status --json`"), "{error}");
    }

    // Added for the boot after the power cut of 2026-10-21 (TODOS.md, "Prove the gateway step on the units").
    // Value: protects=a serve config of `{}` from a tailscaled that has no netmap yet is named as that, not as a
    // wrong handler, and a tailscaled that runs (or whose state cannot be read) still gets the mismatch error;
    // fails_when=the state is not read, a state other than Running hides nothing, or Running hides the mismatch;
    // why_new=the check read only the serve config; seam=none
    #[test]
    fn a_tailscaled_that_does_not_run_yet_is_the_cause_of_a_mismatch() {
        const STATUS: &str = "tailscale status --json --peers=false";
        let runner = FakeRunner::default();
        runner.on("tailscale serve status --json", output(0, "{}"));
        for (status, cause) in [
            (output(0, r#"{"BackendState":"NoState","Self":{}}"#), Some("tailscaled does not run yet (BackendState \"NoState\")")),
            (output(0, r#"{"BackendState":"Starting"}"#), Some("tailscaled does not run yet (BackendState \"Starting\")")),
            (output(1, r#"{"BackendState":"Stopped"}"#), Some("tailscaled does not run yet (BackendState \"Stopped\")")),
            (output(0, r#"{"BackendState":"Running"}"#), None),
            (output(1, ""), None),
            (output(0, "{}"), None),
        ] {
            runner.on(STATUS, status);
            assert_eq!(not_running(&runner).as_deref().map(|text| &text[..cause.map_or(0, str::len)]), cause);
            let error = check(&runner, URL).unwrap_err();
            match cause {
                Some(cause) => assert!(error.starts_with(cause) && error.contains("run grant again"), "{error}"),
                None => assert!(error.starts_with("the serve config of tailscaled is {}"), "{error}"),
            }
        }
        // The one handler needs no state: the state is read only for a mismatch.
        let runner = FakeRunner::default();
        runner.on("tailscale serve status --json", output(0, PROCEDURE));
        runner.on(STATUS, output(0, r#"{"BackendState":"NoState"}"#));
        assert_eq!(check(&runner, URL), Ok(()));
        assert_eq!(runner.calls(), ["tailscale serve status --json"]);
    }

    #[test]
    fn serve_config_that_cannot_be_read_is_an_error() {
        let runner = FakeRunner::default();
        runner.on("tailscale serve status --json", output(0, PROCEDURE));
        assert_eq!(check(&runner, URL), Ok(()));
        assert_eq!(runner.calls(), ["tailscale serve status --json"]);
        for answer in [output(1, ""), output(0, ""), output(0, "No serve config\n")] {
            runner.on("tailscale", answer);
            let error = check(&runner, URL).unwrap_err();
            assert!(error.starts_with("cannot read the serve config of tailscaled"), "{error}");
        }
    }

    // Value: protects=the handler that this check requires is the handler of the procedure that install.sh
    // prints and of its warning; fails_when=one copy changes (the Caddy address or the port) and grant refuses
    // each pass on a correct setup, or install.sh warns about the wrong handler; seam=none
    #[test]
    fn handler_is_the_handler_of_the_procedure_in_install_sh() {
        let install = include_str!("../install.sh");
        assert!(install.contains("tailscale funnel --bg --tcp=443 tcp://127.0.0.1:443\n"));
        assert!(install.contains(r#"'"TCPForward": *"127\.0\.0\.1:443"'"#));
        let setup = include_str!("../setup.sh");
        assert!(setup.contains("tailscale funnel --bg --tcp=443 tcp://127.0.0.1:443\n"));
        assert!(setup.contains(r#"'"TCPForward": *"127\.0\.0\.1:443"'"#));
    }
}
