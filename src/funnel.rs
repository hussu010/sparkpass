//! The inbound route: Tailscale Funnel with raw TCP passthrough to Caddy (owner decision of 2026-10-07). A stop
//! of Caddy does not close another handler of tailscaled, for example a Funnel handler straight to the model
//! server, so grant refuses and reconcile notifies while the serve config is not the one handler of the
//! procedure in install.sh (TODOS.md, "Check the Funnel setup in reconcile and install.sh").

use crate::config;
use crate::runner::{Runner, run_ok};
use serde_json::{Value, json};

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
    // The Funnel name has no user part ("u:PASSWORD@"), so the error text also holds no password.
    let name = host.rsplit_once('@').map_or(host, |(_, name)| name);
    // tailscaled writes the DNS name in lower case; Caddy and TLS compare names with no regard to case.
    let site = format!("{}{}", name.to_ascii_lowercase(), if port.is_empty() { ":443" } else { port });
    let mut expected = json!({"TCP": {"443": {"TCPForward": "127.0.0.1:443"}}, "AllowFunnel": {}});
    expected["AllowFunnel"][&site] = json!(true);
    (*serve != expected).then(|| {
        format!(
            "the serve config of tailscaled is {serve}, and it must be exactly {expected}: a stop of the gateway does not close another handler of tailscaled, for example one straight to the model server; see `tailscale funnel status`, then `tailscale funnel reset` and `tailscale funnel --bg --tcp=443 tcp://127.0.0.1:443`"
        )
    })
}

/// Grant step 1: the serve config is the one handler of the inbound route.
pub fn check(runner: &dyn Runner, public_url: &str) -> Result<(), String> {
    mismatch(&serve_config(runner)?, public_url).map_or(Ok(()), Err)
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
    }
}
