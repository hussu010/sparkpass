//! `sparkpass grant`. Step numbers are the numbers of the design document:
//!
//! ```text
//! flock
//!  1 validate inputs, model health, gateway active, no lease, firewall rules;
//!    a token file that is not deny-all (a key with no lease) ──▶ close the gateway; end-timer call;
//!    then read the clock: deadline = now + TTL (main refuses a TTL shorter than steps 3 to 8, 60 s)
//!  2 lease file (atomic write)          ── from here, each failure runs revoke
//!  3 end timer for the deadline
//!  4 token (not active)
//!  5 home image                         [build phase 2]
//!  6 workspace container                [build phase 2]
//!  7 activate the token, reload Caddy
//!  8 self-check (D5): 200 with the token, 401 with a wrong token (GET and POST)
//!    ── fail ──▶ stop Caddy, revoke, exit non-zero
//!  9 print the pass
//! ```

use crate::config::{self, Paths, Settings};
use crate::gateway;
use crate::lease::{self, Lease, State};
use crate::revoke::revoke;
use crate::runner::{Runner, exit_text, run_ok};
use crate::time::format_utc;
use std::io::{self, Write};

/// Time limit of each curl call, in seconds. It must stay below the command limit in main.rs,
/// so that curl reports its own error before the runner kills it.
const CURL_LIMIT: &str = "8";

/// The longest time of steps 3 to 8: six commands (systemd-run, the timer check, the reload, and the three
/// self-check requests), each with the command limit of main.rs. main refuses a shorter TTL, so that a key
/// never goes live after its end time.
pub const HAND_OUT_TIME: u64 = 6 * crate::COMMAND_LIMIT.as_secs();

/// A token that no grant ever hands out: `new_token` gives 64 random hex characters.
const WRONG_TOKEN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Returns the pass text. main checked the name and the TTL before this call (the first part of step 1).
pub fn grant(paths: &Paths, runner: &dyn Runner, name: &str, ttl: u64, clock: &dyn Fn() -> u64) -> Result<String, String> {
    let _lock = paths
        .lock()
        .map_err(|e| format!("cannot take the lock {}: {e}", paths.lock.display()))?;
    // 1. Validate before any state is written.
    let settings = config::read_settings(paths)?;
    let model = model_name(runner, settings.model_port)?;
    // Only reconcile starts the gateway (the boot gate). Without this check, step 7 fails late.
    run_ok(runner, &["systemctl", "is-active", "--quiet", "caddy"])
        .map_err(|_| "the gateway is not running; run `sparkpass reconcile` and read its output".to_string())?;
    let leases = lease::read_all(paths)
        .map_err(|e| format!("cannot read the lease directory {}: {e}", paths.leases.display()))?;
    if let Some((file, _)) = leases.first() {
        return Err(format!("a lease exists ({file}), and only one guest has access at a time; see `sparkpass list`"));
    }
    run_ok(runner, &[config::FIREWALL]).map_err(|e| format!("the firewall rules did not load: {e}"))?;
    // With no lease, the token file must be the deny-all rule. Other content is a key with no end (a lost
    // lease file) or a cut file: close it here, as the reconcile gate does, with a limit for each command.
    // The end-timer call below is then a pure no-op, so each of its failures means a wrong build.
    if !gateway::is_deny_all(paths) {
        gateway::close(paths, runner).map_err(|e| format!("the token file held a rule with no lease, and the close failed: {e}"))?;
        // Not eprintln!: a failed write to stderr must not panic.
        let _ = writeln!(io::stderr(), "sparkpass: grant: the token file held a rule with no lease; the gateway closed it");
    }
    // The end timer runs this binary with this argv at the deadline. A missing file, or an old build that
    // refuses `--deadline` (exit code 2), fails only then, and the key stays live. Deadline 0 is the end
    // timer of no lease: this build does nothing and takes no lock.
    run_ok(runner, &[config::BINARY, "revoke", name, "--deadline", "0"]).map_err(|e| {
        format!("the end timer needs {}, and it does not accept the call of the end timer: {e}; install this build first", config::BINARY)
    })?;
    // The clock after the lock and after the commands above (up to 50 seconds): neither shortens the TTL,
    // and the end timer counts the TTL from here, also after a backward clock step.
    let now = clock();
    let deadline = now.checked_add(ttl).ok_or("the TTL is too large")?;

    let lease = Lease {
        name: name.into(),
        start: now,
        deadline,
        state: State::Active,
    };
    match hand_out(paths, runner, &settings, &lease, clock) {
        Ok(token) => Ok(pass_text(&settings, &token, &model, deadline)),
        // The token is not printed. The revoke does nothing if the lease file was not written. The end
        // time in the history record is the time of the revoke: the key can have been live since step 7.
        Err(e) => Err(match revoke(paths, runner, name, clock().max(now), false) {
            Ok(()) => format!("grant failed: {e}; no pass was handed out"),
            Err(revoke) => format!("grant failed: {e}; {revoke}"),
        }),
    }
}

/// Step 1: the model must answer. Returns the model name.
fn model_name(runner: &dyn Runner, port: u16) -> Result<String, String> {
    // ponytail: the port comes from MODEL_PORT and the name from the live endpoint, because the
    // schema of templates/pair.yaml is unknown until the hardware step. Upgrade: read both from the recipe.
    let url = format!("http://127.0.0.1:{port}/v1/models");
    let out = run_ok(runner, &["curl", "-q", "--noproxy", "*", "-fsS", "-m", CURL_LIMIT, &url])
        .map_err(|e| format!("the model endpoint is not healthy: {e}"))?;
    serde_json::from_str::<serde_json::Value>(&out.stdout)
        .ok()
        .and_then(|json| Some(json["data"][0]["id"].as_str()?.to_string()))
        .filter(|id| !id.is_empty())
        .ok_or_else(|| format!("the model endpoint is not healthy: {url} gave no model name"))
}

/// Steps 2 to 8. Returns the token. After an error, the caller runs revoke.
fn hand_out(paths: &Paths, runner: &dyn Runner, settings: &Settings, lease: &Lease, clock: &dyn Fn() -> u64) -> Result<String, String> {
    // 2. Lease file with the absolute deadline.
    lease::write(paths, lease).map_err(|e| format!("cannot write the lease file: {e}"))?;
    // 3. End timer. Nothing is handed out before this step: the token file is still the deny-all rule.
    // The step fails if the timer is not active after it.
    lease::create_end_timer(runner, lease, lease.start)?;
    // 4. Token. It is not active yet.
    let token = gateway::new_token().map_err(|e| format!("cannot make a token: {e}"))?;
    // 5 and 6 are build phase 2: home image and workspace container.
    // 7. Activate the token. The model server is not touched. A sync stall in step 2 or a forward clock
    // step can pass the deadline before this point; when it passed before systemd-run, only the monotonic
    // trigger (the full TTL) is left. The key must not go live after its end time. The check looks forward
    // only, so a backward step cannot make it fire.
    // ponytail: the token write and the reload after this check have a window (a sync stall in the token
    // write). When the end timer closes the gateway before that write, grant writes the key over the
    // deny-all rule, and the end timer cuts it only after grant releases the lock (the rest of steps 7 and 8).
    if clock() >= lease.deadline {
        return Err("the deadline passed before the token was active".into());
    }
    gateway::write_rule(paths, &gateway::rule(Some((&lease.name, &token))))
        .map_err(|e| format!("cannot write the token file {}: {e}", paths.token.display()))?;
    run_ok(runner, &["systemctl", "reload", "caddy"])?;
    // 8. Self-check through the public listener (eng review D5). Each failure leaves the gateway with no
    // proof that it refuses a wrong token, and a revoke cannot close a gateway that ignores the token file:
    // the gateway stops (fail closed), and the next reconcile starts it with its own check.
    let models = format!("{}/v1/models", settings.public_url);
    match status(runner, &["-H", &format!("Authorization: Bearer {token}")], &models) {
        Ok(code) if code == "200" => {}
        Ok(code) => return Err(format!(
            "the self-check through {models} failed: the gateway answered {code}, and it must answer 200; {}",
            gateway::stop(runner)
        )),
        Err(e) => return Err(format!("the self-check through {models} failed: {e}; {}", gateway::stop(runner))),
    }
    // The same requests with a wrong token must get 401, also on the route of the model. A gateway that
    // does not import the token file, or a rule that checks only that a header exists, passes the
    // request above for everyone, and only these requests show it.
    match wrong_token_answer(runner, &[], &settings.public_url) {
        None => {}
        // The gateway is open to all, and the revoke cannot close it: a new token file changes nothing.
        Some((url, Ok(code))) => return Err(format!(
            "the gateway answered {code} through {url} to a request with a wrong token, and it must answer 401: the gateway does not enforce the token file; {}; repair the import of the token file in the Caddyfile before the next reconcile starts the gateway",
            gateway::stop(runner)
        )),
        Some((url, Err(e))) => return Err(format!("the self-check with a wrong token through {url} failed: {e}; {}", gateway::stop(runner))),
    }
    Ok(token)
}

/// Step 8 and the reconcile check: a GET of the model list and a POST to the route of the model, each
/// with a wrong token and with `extra` first. The URL and the answer of the first request that did not
/// get 401, or `None` when both got 401. Grant and reconcile send the same requests: after each start,
/// reconcile stops again a gateway that grant stopped (when both reach the same listener).
pub fn wrong_token_answer(runner: &dyn Runner, extra: &[&str], public_url: &str) -> Option<(String, Result<String, String>)> {
    let wrong = format!("Authorization: Bearer {WRONG_TOKEN}");
    let post = ["-H", &wrong, "-H", "Content-Type: application/json", "-d", "{}"];
    for (args, route) in [(&post[..2], "models"), (&post[..], "chat/completions")] {
        let url = format!("{public_url}/v1/{route}");
        match status(runner, &[extra, args].concat(), &url) {
            Ok(code) if code == "401" => {}
            answer => return Some((url, answer)),
        }
    }
    None
}

/// Step 8 and the reconcile check: the HTTP status of one request through curl, with `args` before the
/// URL, or the curl failure. No argv and no stderr in the error, because the argv holds the token.
fn status(runner: &dyn Runner, args: &[&str], url: &str) -> Result<String, String> {
    // ponytail: the token is in the argv, thus in the process list of the host for the time of this
    // command. The host has one owner. Upgrade: give the header to curl in a file (-H @file).
    // -q first: root's ~/.curlrc cannot add options such as --insecure, --proxy, or -L. --noproxy: a
    // proxy from the environment (https_proxy, ALL_PROXY) would skip --connect-to and see the pass key.
    let head = ["curl", "-q", "--noproxy", "*", "-sS", "-o", "/dev/null", "-m", CURL_LIMIT, "-w", "%{http_code}"];
    match runner.run(&[&head[..], args, &[url]].concat()) {
        Ok(out) if out.code == Some(0) => Ok(out.stdout.trim().to_string()),
        Ok(out) => Err(format!("curl {}", exit_text(out.code))),
        Err(e) => Err(format!("curl: {e}")),
    }
}

/// Step 9.
fn pass_text(settings: &Settings, token: &str, model: &str, deadline: u64) -> String {
    format!(
        "Endpoint: {}/v1
API key:  {token}
Model:    {model}
End time: {}

Rules:
- The end time does not move. A model failure or a restart of the host adds no time.
- At the end time the key stops, and open requests close.
- Prompts and completions are not logged. The delete at the end is not a secure erase: the model server can hold recent prompts in its memory until it restarts.
- The owner keeps the lease record (name, start, end) and the gateway access log (time, client IP address, method, path, status, size).
- Acceptable use: no unlawful use, no attack on other systems, and no resale of the access.",
        settings.public_url,
        format_utc(deadline)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::{files, seed};
    use crate::runner::fake::{FakeRunner, output};
    use crate::runner::{Output, RunError};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const NOW: u64 = 1_709_210_096;
    const TTL: u64 = 300;
    const END: u64 = NOW + TTL;
    const HEALTH: &str = "curl -q --noproxy * -fsS -m 8 http://127.0.0.1:8000/v1/models";
    const FIREWALL: &str = config::FIREWALL;
    const BINARY_CHECK: &str = "/usr/local/bin/sparkpass revoke bob --deadline 0";
    const CADDY_ACTIVE: &str = "systemctl is-active --quiet caddy";
    const TIMER: &str = "systemd-run --collect --unit=sparkpass-end-bob-1709210396 --on-calendar=2024-02-29 12:39:56 UTC --on-active=300 --timer-property=AccuracySec=1s --timer-property=RemainAfterElapse=no --property=Type=oneshot --property=TimeoutStartSec=120 /usr/local/bin/sparkpass revoke bob --deadline 1709210396";
    const RELOAD: &str = "systemctl reload caddy";
    /// The start of each of the three self-check requests. The first request has the pass key after it.
    const SELF_CHECK: &str = "curl -q --noproxy * -sS -o /dev/null -m 8 -w %{http_code} -H Authorization: Bearer ";
    const WRONG_GET: &str = "curl -q --noproxy * -sS -o /dev/null -m 8 -w %{http_code} -H Authorization: Bearer 0000000000000000000000000000000000000000000000000000000000000000 https://spark.example.net/v1/models";
    const WRONG_POST: &str = "curl -q --noproxy * -sS -o /dev/null -m 8 -w %{http_code} -H Authorization: Bearer 0000000000000000000000000000000000000000000000000000000000000000 -H Content-Type: application/json -d {} https://spark.example.net/v1/chat/completions";
    const MODELS: &str = "https://spark.example.net/v1/models";
    const CHAT: &str = "https://spark.example.net/v1/chat/completions";
    const STOP_CADDY: &str = "systemctl stop caddy";
    const STOP_TIMER: &str = "systemctl stop sparkpass-end-bob-1709210396.timer";
    const CHECK_TIMER: &str = "systemctl is-active --quiet sparkpass-end-bob-1709210396.timer";
    const RESTART: &str = "systemctl try-restart caddy";

    fn host() -> (Paths, FakeRunner) {
        (Paths::temp(), FakeRunner::healthy())
    }

    /// 64 hex characters in a row: a token, or something that looks like one.
    fn holds_a_token(text: &str) -> bool {
        text.as_bytes().windows(64).any(|w| w.iter().all(u8::is_ascii_hexdigit))
    }

    /// A refused grant: an error, and no state was written.
    fn assert_refused(paths: &Paths, runner: &FakeRunner, before: &[(std::path::PathBuf, String)]) {
        let result = grant(paths, runner, "bob", TTL, &|| NOW);
        assert!(result.is_err(), "{result:?}");
        assert_eq!(paths.snapshot(), before);
        // A refusal reads the host (health, is-active) but changes nothing on it.
        for command in ["systemd-run", "systemctl reload", "systemctl try-restart", "systemctl stop", "systemctl start"] {
            assert_eq!(runner.count(command), 0, "{:?}", runner.calls());
        }
    }

    /// A grant that failed after step 2: revoke ran, access is cut, and the error has no token.
    fn assert_revoked(paths: &Paths, runner: &FakeRunner, result: Result<String, String>) {
        let error = result.unwrap_err();
        assert!(!holds_a_token(&error), "{error}");
        // Extended by the /ship test coverage audit (2026-10-06): the text after a complete revoke.
        // Value: protects=a grant that failed after step 2 and whose revoke completed tells the owner that no pass was handed out;
        // fails_when=the Ok branch after revoke drops or changes the text, and the owner cannot tell a handed-out pass from none;
        // why_new=the five callers of this helper asserted only that the error holds no token; seam=none
        assert!(error.contains("no pass was handed out"), "{error}");
        assert!(gateway::is_deny_all(paths));
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
        assert_eq!(files(&paths.history), [format!("bob-{NOW}.json")]);
        let calls = runner.calls();
        assert!(calls.ends_with(&[RESTART.into(), STOP_TIMER.into(), CHECK_TIMER.into()]), "{calls:?}");
    }

    #[test]
    fn grant_returns_the_pass_after_the_self_check() {
        let (paths, runner) = host();
        let pass = grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap();

        let token = gateway::token_in(&paths.token).unwrap();
        assert_eq!(token.len(), 64);
        assert_eq!(fs::read_to_string(&paths.token).unwrap(), gateway::rule(Some(("bob", &token))));
        for part in [
            "Endpoint: https://spark.example.net/v1\n",
            &format!("API key:  {token}\n"),
            "Model:    test-model\n",
            "End time: 2024-02-29 12:39:56 UTC\n",
            "The end time does not move",
            "the key stops, and open requests close",
            "not logged",
            "not a secure erase",
            "until it restarts",
            "The owner keeps the lease record (name, start, end) and the gateway access log (time, client IP address, method, path, status, size).",
            "no unlawful use, no attack on other systems, and no resale",
        ] {
            assert!(pass.contains(part), "{part:?} is not in:\n{pass}");
        }

        let self_check = format!("{SELF_CHECK}{token} {MODELS}");
        assert_eq!(
            runner.calls(),
            [HEALTH, CADDY_ACTIVE, FIREWALL, BINARY_CHECK, TIMER, CHECK_TIMER, RELOAD, &self_check, WRONG_GET, WRONG_POST]
        );
        let argv = runner.argv();
        let (key, wrong) = (format!("Authorization: Bearer {token}"), format!("Authorization: Bearer {WRONG_TOKEN}"));
        let curl = ["curl", "-q", "--noproxy", "*", "-sS", "-o", "/dev/null", "-m", "8", "-w", "%{http_code}", "-H"];
        assert_eq!(
            argv[argv.len() - 3..],
            [
                [&curl[..], &[key.as_str(), MODELS]].concat(),
                [&curl[..], &[wrong.as_str(), MODELS]].concat(),
                [&curl[..], &[wrong.as_str(), "-H", "Content-Type: application/json", "-d", "{}", CHAT]].concat(),
            ]
        );
        assert_eq!(argv[0], ["curl", "-q", "--noproxy", "*", "-fsS", "-m", "8", "http://127.0.0.1:8000/v1/models"]);
        assert_eq!(argv[3], [config::BINARY, "revoke", "bob", "--deadline", "0"]);
        let lease = Lease { name: "bob".into(), start: NOW, deadline: END, state: State::Active };
        assert_eq!(lease::read(&paths, "bob"), Ok(Some(lease)));
        assert_eq!(files(&paths.history), [] as [&str; 0]);
    }

    #[test]
    fn self_check_with_the_pass_key_must_get_200() {
        let stderr = "curl: (7) Failed to connect".to_string();
        for (check, text) in [
            (output(0, "204"), "the gateway answered 204, and it must answer 200"),
            (output(0, "302"), "the gateway answered 302,"),
            (output(0, "500"), "the gateway answered 500,"),
            (output(0, "401"), "the gateway answered 401,"),
            (Ok(Output { code: Some(7), stdout: "000".into(), stderr }), "curl exit code 7"),
            (Ok(Output { code: None, stdout: String::new(), stderr: String::new() }), "curl ended by a signal"),
            (Err(RunError::Timeout(Duration::from_secs(10))), "curl: no result after 10s"),
            (Err(RunError::Spawn("No such file or directory".into())), "curl: the command did not start"),
        ] {
            let (paths, runner) = host();
            // Also the rule of the wrong-key requests, but they must not run.
            runner.on(SELF_CHECK, check);
            let result = grant(&paths, &runner, "bob", TTL, &|| NOW);

            let calls = runner.calls();
            let token = calls.iter().find_map(|call| call.strip_prefix(SELF_CHECK)).unwrap();
            let token = token.split(' ').next().unwrap();
            assert_eq!(token.len(), 64);
            let error = result.as_ref().unwrap_err();
            assert!(error.contains(&format!("the self-check through {MODELS} failed: {text}")), "{error}");
            // No argv and no stderr of curl in the error.
            assert!(!error.contains(token) && !error.contains("Failed to connect"), "{error}");
            assert_eq!(runner.count(SELF_CHECK), 1);
            // No proof that the gateway refuses a wrong token: it stops before the revoke.
            assert_eq!(runner.count(STOP_CADDY), 1);
            assert_revoked(&paths, &runner, result);
        }
    }

    // A curl failure is no answer, thus no proof that the gateway refuses a wrong token, and the revoke cannot
    // close a gateway that ignores the token file: grant stops the gateway, then revokes.
    #[test]
    fn self_check_with_a_wrong_token_fails_when_curl_fails() {
        for (request, url, runs) in [(WRONG_GET, MODELS, 2), (WRONG_POST, CHAT, 3)] {
            for (check, text) in [
                (output(7, "000"), "curl exit code 7"),
                (output(28, "000"), "curl exit code 28"),
                (Err(RunError::Timeout(Duration::from_secs(10))), "curl: no result after 10s"),
            ] {
                let (paths, runner) = host();
                runner.on(request, check);
                let result = grant(&paths, &runner, "bob", TTL, &|| NOW);
                let error = result.as_ref().unwrap_err();
                assert!(error.contains(&format!("the self-check with a wrong token through {url} failed: {text}")), "{error}");
                assert_eq!(runner.count(SELF_CHECK), runs);
                assert_eq!(runner.count(STOP_CADDY), 1);
                let calls = runner.calls();
                assert!(calls.ends_with(&[STOP_CADDY, RESTART, STOP_TIMER, CHECK_TIMER].map(String::from)), "{calls:?}");
                assert_revoked(&paths, &runner, result);
            }
        }
    }

    // A gateway that does not enforce the token file is open to all, and a revoke cannot close it.
    #[test]
    fn wrong_token_that_is_not_refused_stops_the_gateway_before_the_revoke() {
        for (request, url, runs) in [(WRONG_GET, MODELS, 2), (WRONG_POST, CHAT, 3)] {
            for code in ["200", "404", "204", "302", "500", ""] {
                let (paths, runner) = host();
                runner.on(request, output(0, code));
                let result = grant(&paths, &runner, "bob", TTL, &|| NOW);
                let error = result.as_ref().unwrap_err();
                for part in [
                    &format!("the gateway answered {code} through {url} to a request with a wrong token, and it must answer 401"),
                    "the gateway does not enforce the token file; the gateway is stopped;",
                    "repair the import of the token file in the Caddyfile before the next reconcile",
                ] {
                    assert!(error.contains(part), "{part:?} is not in: {error}");
                }
                assert_eq!(runner.count(SELF_CHECK), runs);
                // One stop, and then the revoke: try-restart has no effect on a stopped gateway.
                assert_eq!(runner.count(STOP_CADDY), 1);
                let calls = runner.calls();
                assert!(calls.ends_with(&[STOP_CADDY, RESTART, STOP_TIMER, CHECK_TIMER].map(String::from)), "{calls:?}");
                assert_revoked(&paths, &runner, result);
            }
        }
    }

    #[test]
    fn lease_file_and_history_record_never_hold_the_token() {
        let (paths, runner) = host();
        grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap();
        let token = gateway::token_in(&paths.token).unwrap();

        let lease = fs::read_to_string(paths.lease("bob")).unwrap();
        assert!(!lease.contains(&token) && !holds_a_token(&lease), "{lease}");
        assert_eq!(fs::metadata(paths.lease("bob")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&paths.leases).unwrap().permissions().mode() & 0o777, 0o700);

        assert_eq!(revoke(&paths, &runner, "bob", NOW + 60, false), Ok(()));
        let record = fs::read_to_string(paths.history.join(format!("bob-{NOW}.json"))).unwrap();
        assert!(!record.contains(&token) && !holds_a_token(&record), "{record}");
        // The token is in no file after the revoke.
        for (path, text) in paths.snapshot() {
            assert!(!text.contains(&token), "{}", path.display());
        }
    }

    #[test]
    fn end_timer_is_created_before_any_credential() {
        let (paths, runner) = host();
        // At the systemd-run call: the token file content, and whether the lease file exists.
        let seen = Arc::new(Mutex::new(Vec::new()));
        runner.hook({
            let (seen, token, lease) = (seen.clone(), paths.token.clone(), paths.lease("bob"));
            move |argv| {
                if argv[0] == "systemd-run" {
                    seen.lock().unwrap().push((fs::read_to_string(&token).unwrap(), lease.exists()));
                }
            }
        });
        grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap();
        assert_eq!(*seen.lock().unwrap(), [(gateway::rule(None), true)]);
        assert!(gateway::token_in(&paths.token).is_some());
    }

    #[test]
    fn failed_end_timer_revokes_before_a_token_exists() {
        for (command, fault) in [
            ("systemd-run", output(1, "")),
            ("systemd-run", Err(RunError::Timeout(Duration::from_secs(10)))),
            // systemd-run gives exit code 0, and no timer is active after it.
            (CHECK_TIMER, output(4, "")),
        ] {
            let (paths, runner) = host();
            runner.on(command, fault);
            let result = grant(&paths, &runner, "bob", TTL, &|| NOW);
            assert_eq!(runner.count("systemd-run"), 1);
            assert_eq!(runner.count(RELOAD), 0);
            assert_eq!(runner.count(SELF_CHECK), 0);
            assert_revoked(&paths, &runner, result);
        }
    }

    #[test]
    fn failed_token_write_revokes() {
        let (paths, runner) = host();
        // The token file is unwritable from the timer step on. The revoke cannot write the deny-all
        // rule either, so it stops the gateway and marks the lease (D7); no token was ever active.
        runner.hook({
            let token = paths.token.clone();
            move |argv| {
                if argv[0] == "systemd-run" {
                    fs::remove_file(&token).unwrap();
                    fs::create_dir(&token).unwrap();
                }
            }
        });
        let error = grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap_err();
        // Extended by the /ship test coverage audit (2026-10-06): the error names the file to repair.
        // Value: protects=the error of a failed token write names the token file path;
        // fails_when=the map_err in hand_out drops paths.token.display(), and the owner reads "Is a directory" with no file;
        // why_new=this test asserted the revoke and the absent token only, not the text; seam=none
        let token_file = paths.token.display().to_string();
        assert!(error.contains(&token_file), "{error}");
        assert!(!holds_a_token(&error), "{error}");
        assert_eq!(runner.count(RELOAD), 0);
        assert_eq!(runner.count(SELF_CHECK), 0);
        assert_eq!(runner.count(RESTART), 0);
        assert_eq!(runner.count("systemctl stop caddy"), 1);
        assert_eq!(lease::read(&paths, "bob").unwrap().unwrap().state, State::RevokeFailed);
    }

    #[test]
    fn failed_reload_revokes_and_returns_no_token() {
        let (paths, runner) = host();
        runner.exit(RELOAD, 1);
        // The token that was in the token file at the reload.
        let seen = Arc::new(Mutex::new(None));
        runner.hook({
            let (seen, token) = (seen.clone(), paths.token.clone());
            move |argv| {
                if argv.join(" ") == RELOAD {
                    *seen.lock().unwrap() = gateway::token_in(&token);
                }
            }
        });
        let result = grant(&paths, &runner, "bob", TTL, &|| NOW);
        let token = seen.lock().unwrap().clone().unwrap();
        assert!(holds_a_token(&token));
        assert!(!result.as_ref().unwrap_err().contains(&token), "{result:?}");
        assert_eq!(runner.count(SELF_CHECK), 0);
        assert_revoked(&paths, &runner, result);
    }

    #[test]
    fn failed_revoke_after_a_failed_grant_step_leaves_a_revoke_failed_lease() {
        let (paths, runner) = host();
        runner.exit(RELOAD, 1);
        runner.exit(RESTART, 1);
        let error = grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap_err();
        assert!(!holds_a_token(&error), "{error}");
        // The error is the only report of the failed revoke: revoke itself writes nothing to the journal.
        assert!(error.contains("the revoke of bob is not complete (state revoke-failed)"), "{error}");
        assert_eq!(lease::read(&paths, "bob").unwrap().unwrap().state, State::RevokeFailed);
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(runner.count("systemctl stop caddy"), 1);
    }

    #[test]
    fn grant_refuses_when_the_model_is_down() {
        for health in [
            output(7, ""),
            output(22, ""),
            // A complete answer, but curl did not end with exit code 0.
            output(28, r#"{"data":[{"id":"test-model"}]}"#),
            Err(RunError::Timeout(Duration::from_secs(10))),
            output(0, ""),
            output(0, "<html>not json</html>"),
            output(0, r#"{"data":[]}"#),
            output(0, r#"{"data":[{"id":""}]}"#),
            output(0, r#"{"data":[{"id":7}]}"#),
            output(0, r#"{"error":"loading"}"#),
        ] {
            let (paths, runner) = host();
            runner.on(HEALTH, health);
            assert_refused(&paths, &runner, &paths.snapshot());
            assert_eq!(runner.calls(), [HEALTH]);
        }
    }

    #[test]
    fn grant_refuses_when_the_gateway_is_not_running() {
        // After a boot or a fail-closed stop, only `sparkpass reconcile` starts the gateway.
        let (paths, runner) = host();
        runner.exit(CADDY_ACTIVE, 3);
        assert_refused(&paths, &runner, &paths.snapshot());
        assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE]);
        let error = grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap_err();
        assert!(error.contains("run `sparkpass reconcile`"), "{error}");
    }

    #[test]
    fn grant_refuses_when_a_lease_exists() {
        for name in ["bob", "amy"] {
            for state in [State::Active, State::RevokeFailed] {
                let (paths, runner) = host();
                seed(&paths, name, END, state);
                assert_refused(&paths, &runner, &paths.snapshot());
                assert_eq!(runner.count(FIREWALL), 0);
            }
        }
    }

    #[test]
    fn grant_refuses_when_a_lease_file_is_unreadable() {
        let (paths, runner) = host();
        fs::write(paths.lease("amy"), "not json").unwrap();
        assert_refused(&paths, &runner, &paths.snapshot());
    }

    #[test]
    fn grant_refuses_when_the_settings_file_is_missing_or_broken() {
        let (paths, runner) = host();
        fs::remove_file(&paths.config).unwrap();
        assert_refused(&paths, &runner, &paths.snapshot());
        assert_eq!(runner.calls(), [] as [&str; 0]);

        let (paths, runner) = host();
        fs::write(&paths.config, "PUBLIC_URL=https://spark.example.net\n").unwrap();
        assert_refused(&paths, &runner, &paths.snapshot());
        assert_eq!(runner.calls(), [] as [&str; 0]);
    }

    #[test]
    fn grant_refuses_when_the_firewall_script_fails() {
        for firewall in [output(1, ""), Err(RunError::Spawn("No such file or directory".into()))] {
            let (paths, runner) = host();
            runner.on(FIREWALL, firewall);
            assert_refused(&paths, &runner, &paths.snapshot());
            assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE, FIREWALL]);
        }
    }

    #[test]
    fn grant_refuses_when_the_end_timer_binary_does_not_run() {
        // Exit code 2: an old build that refuses `--deadline` (a usage error). 126: not executable.
        for check in [output(2, ""), output(1, ""), output(126, ""), Err(RunError::Spawn("No such file or directory".into()))] {
            let (paths, runner) = host();
            runner.on(BINARY_CHECK, check);
            assert_refused(&paths, &runner, &paths.snapshot());
            assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE, FIREWALL, BINARY_CHECK]);
            let error = grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap_err();
            assert!(error.contains(config::BINARY) && error.contains("install this build first"), "{error}");
        }
    }

    #[test]
    fn grant_refuses_when_the_lock_cannot_be_taken() {
        let (paths, runner) = host();
        // The lock file path is a directory, so the lock cannot be opened.
        let _ = fs::remove_file(&paths.lock);
        fs::create_dir(&paths.lock).unwrap();
        let before = paths.snapshot();
        let error = grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap_err();
        assert!(error.contains("cannot take the lock"), "{error}");
        assert_eq!(runner.calls(), [] as [&str; 0]);
        assert_eq!(paths.snapshot(), before);
    }

    // Step 2 fails: nothing is handed out. A token with no lease file has no end.
    #[test]
    fn grant_refuses_when_the_lease_file_cannot_be_written() {
        let (paths, runner) = host();
        // The temporary file of the atomic write cannot be created. `read_all` ignores this name.
        fs::create_dir(paths.leases.join("bob.json.tmp")).unwrap();
        assert_refused(&paths, &runner, &paths.snapshot());
        assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE, FIREWALL, BINARY_CHECK]);
    }

    #[test]
    fn grant_reads_the_model_port_from_the_settings_file() {
        let (paths, runner) = host();
        fs::write(&paths.config, "PUBLIC_URL=https://10.0.0.5:8443\nMODEL_PORT=9001\nGATEWAY_CHECK_ADDRESS=127.0.0.1\n").unwrap();
        runner.on("curl -q --noproxy * -fsS -m 8 http://127.0.0.1:9001/v1/models", output(0, r#"{"data":[{"id":"m2"}]}"#));
        let pass = grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap();
        assert!(pass.contains("Endpoint: https://10.0.0.5:8443/v1\n") && pass.contains("Model:    m2\n"), "{pass}");
        let calls = runner.calls();
        let urls: Vec<_> = calls[calls.len() - 3..].iter().map(|call| call.rsplit(' ').next().unwrap()).collect();
        assert_eq!(urls, ["https://10.0.0.5:8443/v1/models", "https://10.0.0.5:8443/v1/models", "https://10.0.0.5:8443/v1/chat/completions"]);
    }

    // Added by the /ship test coverage audit (2026-10-06).
    // Value: protects=each curl call ends by its own -m limit before the runner kills it, so a failed self-check reports the curl exit code;
    // fails_when=CURL_LIMIT is raised to or above COMMAND_LIMIT, and the runner reports "no result after 10s" in place of the curl error;
    // why_new=the argv tests pin "-m 8" but nothing relates it to the runner limit in main.rs; seam=none
    #[test]
    fn curl_limit_is_below_the_command_limit() {
        let curl: u64 = CURL_LIMIT.parse().unwrap();
        assert!(Duration::from_secs(curl) < crate::COMMAND_LIMIT, "{curl}s against {:?}", crate::COMMAND_LIMIT);
    }

    #[test]
    fn grant_reads_the_clock_after_the_lock() {
        let (paths, runner) = host();
        let clock = AtomicU64::new(NOW - 120);
        std::thread::scope(|scope| {
            // In the scope: a failed assert drops the lock, and the test fails and does not hang.
            let lock = paths.lock().unwrap();
            let granter = scope.spawn(|| grant(&paths, &runner, "bob", TTL, &|| clock.load(Ordering::SeqCst)));
            std::thread::sleep(Duration::from_millis(200));
            assert!(!granter.is_finished());
            // The wait for the lock took 2 minutes.
            clock.store(NOW, Ordering::SeqCst);
            drop(lock);
            assert!(granter.join().unwrap().is_ok());
        });
        // The guest gets the full TTL from the end of the wait.
        let lease = Lease { name: "bob".into(), start: NOW, deadline: END, state: State::Active };
        assert_eq!(lease::read(&paths, "bob"), Ok(Some(lease)));
        assert_eq!(runner.count(TIMER), 1, "{:?}", runner.calls());
    }

    #[test]
    fn grant_reads_the_clock_after_the_checks_of_step_1() {
        // The checks of step 1 take 40 seconds, or the clock steps back by one hour during them. The
        // deadline is the TTL after the read that follows them, and the end timer counts the full TTL.
        for after_checks in [NOW + 40, NOW - 3_600] {
            let (paths, runner) = host();
            let clock = Arc::new(AtomicU64::new(NOW));
            runner.hook({
                let clock = clock.clone();
                move |argv| {
                    if argv.join(" ") == BINARY_CHECK {
                        clock.store(after_checks, Ordering::SeqCst);
                    }
                }
            });
            grant(&paths, &runner, "bob", TTL, &|| clock.load(Ordering::SeqCst)).unwrap();
            let lease = Lease { name: "bob".into(), start: after_checks, deadline: after_checks + TTL, state: State::Active };
            assert_eq!(lease::read(&paths, "bob"), Ok(Some(lease)));
            let calls = runner.calls();
            let timer = calls.iter().find(|call| call.starts_with("systemd-run")).unwrap();
            assert!(timer.contains(" --on-active=300 ") && timer.ends_with(&format!(" --deadline {}", after_checks + TTL)), "{timer}");
        }
    }

    #[test]
    fn history_end_is_the_clock_of_the_revoke_after_a_failed_grant_step() {
        // The reload fails 30 seconds after the checks: the record ends then, not at the start.
        let (paths, runner) = host();
        let clock = Arc::new(AtomicU64::new(NOW));
        runner.hook({
            let clock = clock.clone();
            move |argv| {
                if argv.join(" ") == RELOAD {
                    clock.store(NOW + 30, Ordering::SeqCst);
                }
            }
        });
        runner.exit(RELOAD, 1);
        let result = grant(&paths, &runner, "bob", TTL, &|| clock.load(Ordering::SeqCst));
        assert_revoked(&paths, &runner, result);
        let record = fs::read_to_string(paths.history.join(format!("bob-{NOW}.json"))).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&record).unwrap()["end"], NOW + 30, "{record}");
    }

    #[test]
    fn deadline_that_passes_before_the_token_is_active_gives_no_pass() {
        // A sync stall or a forward clock step during steps 2 and 3 takes the whole TTL. A backward step
        // does not make the check fire.
        for (clock_at_timer, refused) in [(END, true), (END + 70, true), (END - 1, false), (NOW - 3_600, false)] {
            let (paths, runner) = host();
            let clock = Arc::new(AtomicU64::new(NOW));
            runner.hook({
                let clock = clock.clone();
                move |argv| {
                    if argv[0] == "systemd-run" {
                        clock.store(clock_at_timer, Ordering::SeqCst);
                    }
                }
            });
            let result = grant(&paths, &runner, "bob", TTL, &|| clock.load(Ordering::SeqCst));
            if refused {
                assert!(result.as_ref().is_err_and(|e| e.contains("the deadline passed before the token was active")), "{result:?}");
                // The token never went live: no reload, and the revoke ran.
                assert_eq!(runner.count(RELOAD), 0);
                assert_revoked(&paths, &runner, result);
            } else {
                assert!(result.is_ok(), "{clock_at_timer}: {result:?}");
            }
        }
    }

    #[test]
    fn history_end_is_not_before_the_start_after_a_backward_clock_step() {
        let (paths, runner) = host();
        let clock = Arc::new(AtomicU64::new(NOW));
        runner.hook({
            let clock = clock.clone();
            move |argv| {
                if argv.join(" ") == RELOAD {
                    clock.store(NOW - 3_600, Ordering::SeqCst);
                }
            }
        });
        runner.exit(RELOAD, 1);
        let result = grant(&paths, &runner, "bob", TTL, &|| clock.load(Ordering::SeqCst));
        assert_revoked(&paths, &runner, result);
        let record = fs::read_to_string(paths.history.join(format!("bob-{NOW}.json"))).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&record).unwrap()["end"], NOW, "{record}");
    }

    #[test]
    fn token_rule_with_no_lease_is_closed_before_the_end_timer_call() {
        // A lost lease file of bob, a key of a different name, or a cut file: each is a key with no lease.
        for text in [gateway::rule(Some(("bob", &"ab".repeat(32)))), gateway::rule(Some(("amy", "cd"))), String::new()] {
            let (paths, runner) = host();
            fs::write(&paths.token, &text).unwrap();
            grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap();
            let calls = runner.calls();
            assert_eq!(calls[..5], [HEALTH, CADDY_ACTIVE, FIREWALL, RESTART, BINARY_CHECK], "{text:?}");
            assert!(gateway::is_rule_of(&paths, "bob"));
            assert_ne!(fs::read_to_string(&paths.token).unwrap(), text);
        }
        // The close fails: the gateway stops, and grant refuses with no lease.
        let (paths, runner) = host();
        fs::write(&paths.token, gateway::rule(Some(("bob", "ab")))).unwrap();
        runner.exit(RESTART, 1);
        let error = grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap_err();
        assert!(error.contains("the token file held a rule with no lease, and the close failed") && error.ends_with("the gateway is stopped"), "{error}");
        assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE, FIREWALL, RESTART, STOP_CADDY]);
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
    }

    #[test]
    fn grant_refuses_a_deadline_that_does_not_fit_after_the_lock() {
        let (paths, runner) = host();
        let before = paths.snapshot();
        assert_eq!(grant(&paths, &runner, "bob", 60, &|| u64::MAX - 59), Err("the TTL is too large".into()));
        // The clock is read after the checks of step 1, and they write nothing.
        assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE, FIREWALL, BINARY_CHECK]);
        assert_eq!(paths.snapshot(), before);
    }

    #[test]
    fn grant_works_again_after_a_revoke() {
        let (paths, runner) = host();
        grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap();
        let first = gateway::token_in(&paths.token).unwrap();
        assert_eq!(revoke(&paths, &runner, "bob", NOW + 60, false), Ok(()));
        grant(&paths, &runner, "bob", TTL, &|| NOW + 120).unwrap();
        assert_ne!(gateway::token_in(&paths.token).unwrap(), first);
    }
}
