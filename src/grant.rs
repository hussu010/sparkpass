//! `sparkpass grant`. Step numbers are the numbers of the design document:
//!
//! ```text
//! flock
//!  1 validate inputs, model health, gateway active, no lease, firewall rules
//!  2 lease file (atomic write)          ── from here, each failure runs revoke
//!  3 end timer for the deadline
//!  4 token (not active)
//!  5 home image                         [build phase 2]
//!  6 workspace container                [build phase 2]
//!  7 activate the token, reload Caddy
//!  8 self-check (D5): 200 with the token, 401 with a wrong token ── fail ──▶ revoke, exit non-zero
//!  9 print the pass
//! ```

use crate::config::{self, Paths, Settings};
use crate::gateway;
use crate::lease::{self, Lease, State};
use crate::revoke::revoke;
use crate::runner::{Runner, exit_text, run_ok};
use crate::time::format_utc;

/// Time limit of each curl call, in seconds. It must stay below the command limit in main.rs,
/// so that curl reports its own error before the runner kills it.
const CURL_LIMIT: &str = "8";

/// A token that no grant ever hands out: `new_token` gives 64 random hex characters.
const WRONG_TOKEN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Returns the pass text. main checked the name and the TTL before this call (the first part of step 1).
pub fn grant(paths: &Paths, runner: &dyn Runner, name: &str, now: u64, deadline: u64) -> Result<String, String> {
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

    let lease = Lease {
        name: name.into(),
        start: now,
        deadline,
        state: State::Active,
    };
    match hand_out(paths, runner, &settings, &lease) {
        Ok(token) => Ok(pass_text(&settings, &token, &model, deadline)),
        // The token is not printed. The revoke does nothing if the lease file was not written.
        Err(e) => Err(match revoke(paths, runner, name, now, false) {
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
    let out = run_ok(runner, &["curl", "-fsS", "-m", CURL_LIMIT, &url])
        .map_err(|e| format!("the model endpoint is not healthy: {e}"))?;
    serde_json::from_str::<serde_json::Value>(&out.stdout)
        .ok()
        .and_then(|json| Some(json["data"][0]["id"].as_str()?.to_string()))
        .filter(|id| !id.is_empty())
        .ok_or_else(|| format!("the model endpoint is not healthy: {url} gave no model name"))
}

/// Steps 2 to 8. Returns the token. After an error, the caller runs revoke.
fn hand_out(paths: &Paths, runner: &dyn Runner, settings: &Settings, lease: &Lease) -> Result<String, String> {
    // 2. Lease file with the absolute deadline.
    lease::write(paths, lease).map_err(|e| format!("cannot write the lease file: {e}"))?;
    // 3. End timer. Nothing is handed out before this step: the token file is still the deny-all rule.
    // The step fails if the timer is not active after it (a deadline that is in the past already).
    lease::create_end_timer(runner, lease, lease.start)?;
    // 4. Token. It is not active yet.
    let token = gateway::new_token().map_err(|e| format!("cannot make a token: {e}"))?;
    // 5 and 6 are build phase 2: home image and workspace container.
    // 7. Activate the token. The model server is not touched.
    gateway::write_rule(paths, &gateway::rule(Some((&lease.name, &token))))
        .map_err(|e| format!("cannot write the token file {}: {e}", paths.token.display()))?;
    run_ok(runner, &["systemctl", "reload", "caddy"])?;
    // 8. Self-check through the public listener (eng review D5).
    // ponytail: the token is in the argv, thus in the process list of the host for the time of this
    // command. The host has one owner. Upgrade: give the header to curl in a file (-H @file).
    let url = format!("{}/v1/models", settings.public_url);
    let header = format!("Authorization: Bearer {token}");
    match runner.run(&["curl", "-fsS", "-o", "/dev/null", "-m", CURL_LIMIT, "-H", &header, &url]) {
        Ok(out) if out.code == Some(0) => {}
        // No argv and no stderr in these texts, because the argv holds the token.
        Ok(out) => return Err(format!("the self-check through {url} failed: curl {}", exit_text(out.code))),
        Err(e) => return Err(format!("the self-check through {url} failed: curl: {e}")),
    }
    // The same request with a wrong token must get 401. A gateway that does not import the token
    // file, or a rule that checks only that a header exists, passes the request above for everyone,
    // and only this request shows it.
    let wrong = format!("Authorization: Bearer {WRONG_TOKEN}");
    match runner.run(&["curl", "-sS", "-o", "/dev/null", "-m", CURL_LIMIT, "-w", "%{http_code}", "-H", &wrong, &url]) {
        Ok(out) if out.code == Some(0) && out.stdout.trim() == "401" => Ok(token),
        Ok(out) if out.code == Some(0) => Err(format!(
            "the gateway answered {} through {url} to a request with a wrong token, and it must answer 401; does the Caddyfile import the token file?",
            out.stdout.trim()
        )),
        Ok(out) => Err(format!("the self-check with a wrong token through {url} failed: curl {}", exit_text(out.code))),
        Err(e) => Err(format!("the self-check with a wrong token through {url} failed: curl: {e}")),
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
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const NOW: u64 = 1_709_210_096;
    const END: u64 = NOW + 300;
    const HEALTH: &str = "curl -fsS -m 8 http://127.0.0.1:8000/v1/models";
    const FIREWALL: &str = config::FIREWALL;
    const CADDY_ACTIVE: &str = "systemctl is-active --quiet caddy";
    const TIMER: &str = "systemd-run --collect --unit=sparkpass-end-bob-1709210396 --on-calendar=2024-02-29 12:39:56 UTC --on-active=300 --timer-property=AccuracySec=1s --timer-property=RemainAfterElapse=no --property=Type=oneshot --property=TimeoutStartSec=120 /usr/local/bin/sparkpass revoke bob";
    const RELOAD: &str = "systemctl reload caddy";
    const SELF_CHECK: &str = "curl -fsS -o /dev/null -m 8 -H Authorization: Bearer ";
    const WRONG_TOKEN_CHECK: &str = "curl -sS -o /dev/null -m 8 -w %{http_code} -H Authorization: Bearer 0000000000000000000000000000000000000000000000000000000000000000 https://spark.example.net/v1/models";
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
        let result = grant(paths, runner, "bob", NOW, END);
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
        let pass = grant(&paths, &runner, "bob", NOW, END).unwrap();

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

        let self_check = format!("{SELF_CHECK}{token} https://spark.example.net/v1/models");
        assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE, FIREWALL, TIMER, CHECK_TIMER, RELOAD, &self_check, WRONG_TOKEN_CHECK]);
        let argv = runner.argv();
        assert_eq!(
            argv[argv.len() - 1][..],
            ["curl", "-sS", "-o", "/dev/null", "-m", "8", "-w", "%{http_code}", "-H", "Authorization: Bearer 0000000000000000000000000000000000000000000000000000000000000000", "https://spark.example.net/v1/models"]
        );
        assert_eq!(
            argv[argv.len() - 2][..],
            [
                "curl",
                "-fsS",
                "-o",
                "/dev/null",
                "-m",
                "8",
                "-H",
                &format!("Authorization: Bearer {token}"),
                "https://spark.example.net/v1/models"
            ]
        );
        let lease = Lease { name: "bob".into(), start: NOW, deadline: END, state: State::Active };
        assert_eq!(lease::read(&paths, "bob"), Ok(Some(lease)));
        assert_eq!(files(&paths.history), [] as [&str; 0]);
    }

    #[test]
    fn failed_self_check_revokes_and_returns_no_token() {
        let stderr = "curl: (22) The requested URL returned error: 401".to_string();
        for check in [
            Ok(Output { code: Some(22), stdout: String::new(), stderr }),
            Ok(Output { code: None, stdout: String::new(), stderr: String::new() }),
            Err(RunError::Timeout(Duration::from_secs(10))),
            Err(RunError::Spawn("No such file or directory".into())),
        ] {
            let (paths, runner) = host();
            runner.on(SELF_CHECK, check);
            let result = grant(&paths, &runner, "bob", NOW, END);

            let calls = runner.calls();
            let token = calls.iter().find_map(|call| call.strip_prefix(SELF_CHECK)).unwrap();
            let token = token.split(' ').next().unwrap();
            assert_eq!(token.len(), 64);
            assert!(!result.as_ref().unwrap_err().contains(token), "{result:?}");
            assert_eq!(runner.count(WRONG_TOKEN_CHECK), 0);
            assert_revoked(&paths, &runner, result);
        }
    }

    #[test]
    fn self_check_with_a_wrong_token_must_get_401() {
        for (check, text) in [
            (output(0, "200"), "answered 200"),
            (output(0, "404"), "answered 404"),
            (output(0, ""), "must answer 401"),
            (output(7, "000"), "curl exit code 7"),
            (Err(RunError::Timeout(Duration::from_secs(10))), "with a wrong token"),
        ] {
            let (paths, runner) = host();
            runner.on(WRONG_TOKEN_CHECK, check);
            let result = grant(&paths, &runner, "bob", NOW, END);
            assert_eq!(runner.count(SELF_CHECK), 1);
            assert_eq!(runner.count(WRONG_TOKEN_CHECK), 1);
            assert!(result.as_ref().unwrap_err().contains(text), "{result:?}");
            assert_revoked(&paths, &runner, result);
        }
    }

    #[test]
    fn lease_file_and_history_record_never_hold_the_token() {
        let (paths, runner) = host();
        grant(&paths, &runner, "bob", NOW, END).unwrap();
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
        grant(&paths, &runner, "bob", NOW, END).unwrap();
        assert_eq!(*seen.lock().unwrap(), [(gateway::rule(None), true)]);
        assert!(gateway::token_in(&paths.token).is_some());
    }

    #[test]
    fn failed_end_timer_revokes_before_a_token_exists() {
        for (command, fault) in [
            ("systemd-run", output(1, "")),
            ("systemd-run", Err(RunError::Timeout(Duration::from_secs(10)))),
            // systemd-run gives exit code 0 for a deadline in the past, and no timer is active after it.
            (CHECK_TIMER, output(4, "")),
        ] {
            let (paths, runner) = host();
            runner.on(command, fault);
            let result = grant(&paths, &runner, "bob", NOW, END);
            assert_eq!(runner.count("systemd-run"), 1);
            assert_eq!(runner.count(RELOAD), 0);
            assert_eq!(runner.count("curl -fsS -o"), 0);
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
        let error = grant(&paths, &runner, "bob", NOW, END).unwrap_err();
        // Extended by the /ship test coverage audit (2026-10-06): the error names the file to repair.
        // Value: protects=the error of a failed token write names the token file path;
        // fails_when=the map_err in hand_out drops paths.token.display(), and the owner reads "Is a directory" with no file;
        // why_new=this test asserted the revoke and the absent token only, not the text; seam=none
        let token_file = paths.token.display().to_string();
        assert!(error.contains(&token_file), "{error}");
        assert!(!holds_a_token(&error), "{error}");
        assert_eq!(runner.count(RELOAD), 0);
        assert_eq!(runner.count("curl -fsS -o"), 0);
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
        let result = grant(&paths, &runner, "bob", NOW, END);
        let token = seen.lock().unwrap().clone().unwrap();
        assert!(holds_a_token(&token));
        assert!(!result.as_ref().unwrap_err().contains(&token), "{result:?}");
        assert_eq!(runner.count("curl -fsS -o"), 0);
        assert_revoked(&paths, &runner, result);
    }

    #[test]
    fn failed_revoke_after_a_failed_grant_step_leaves_a_revoke_failed_lease() {
        let (paths, runner) = host();
        runner.exit(RELOAD, 1);
        runner.exit(RESTART, 1);
        let error = grant(&paths, &runner, "bob", NOW, END).unwrap_err();
        assert!(!holds_a_token(&error), "{error}");
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
        let error = grant(&paths, &runner, "bob", NOW, END).unwrap_err();
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
    fn grant_refuses_when_the_lock_cannot_be_taken() {
        let (paths, runner) = host();
        // The lock file path is a directory, so the lock cannot be opened.
        let _ = fs::remove_file(&paths.lock);
        fs::create_dir(&paths.lock).unwrap();
        let before = paths.snapshot();
        let error = grant(&paths, &runner, "bob", NOW, END).unwrap_err();
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
        assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE, FIREWALL]);
    }

    #[test]
    fn grant_reads_the_model_port_from_the_settings_file() {
        let (paths, runner) = host();
        fs::write(&paths.config, "PUBLIC_URL=https://10.0.0.5:8443\nMODEL_PORT=9001\n").unwrap();
        runner.on("curl -fsS -m 8 http://127.0.0.1:9001/v1/models", output(0, r#"{"data":[{"id":"m2"}]}"#));
        let pass = grant(&paths, &runner, "bob", NOW, END).unwrap();
        assert!(pass.contains("Endpoint: https://10.0.0.5:8443/v1\n") && pass.contains("Model:    m2\n"), "{pass}");
        assert!(runner.calls().last().unwrap().ends_with(" https://10.0.0.5:8443/v1/models"));
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
    fn grant_works_again_after_a_revoke() {
        let (paths, runner) = host();
        grant(&paths, &runner, "bob", NOW, END).unwrap();
        let first = gateway::token_in(&paths.token).unwrap();
        assert_eq!(revoke(&paths, &runner, "bob", NOW + 60, false), Ok(()));
        grant(&paths, &runner, "bob", NOW + 120, END + 120).unwrap();
        assert_ne!(gateway::token_in(&paths.token).unwrap(), first);
    }
}
