//! `sparkpass grant`. Step numbers are the numbers of the design document:
//!
//! ```text
//! flock
//!  1 validate inputs, no gateway-open marker, no lease, model health, gateway active;
//!    a wrong token (GET and POST) to the public listener at GATEWAY_CHECK_ADDRESS gets no 401
//!    ── fail ──▶ stop Caddy, exit non-zero (a proven answer: write gateway-open);
//!    firewall rules; a token file that is not deny-all (a key with no lease) ──▶ close the gateway;
//!    end-timer call; then read the clock: deadline = now + TTL (main refuses a TTL shorter than steps 3 to 8, 60 s)
//!  2 lease file (atomic write)          ── from here, each failure runs revoke
//!  3 end timer for the deadline
//!  4 token (not active)
//!  5 home image                         [build phase 2]
//!  6 workspace container                [build phase 2]
//!  7 activate the token, reload Caddy
//!  8 self-check (D5) through PUBLIC_URL: 200 with the token, 401 with a wrong token (GET and POST)
//!    ── fail ──▶ stop Caddy, revoke, exit non-zero; an answer other than 401 is no proof by itself (the
//!    inbound route can answer): the check of step 1 decides, and only its proven answer writes gateway-open
//!  9 print the pass
//! ```

use crate::config::{self, Paths, Settings};
use crate::gateway;
use crate::lease::{self, Lease, State};
use crate::revoke::revoke;
use crate::runner::{Runner, exit_text, run_ok};
use crate::time::format_utc;
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;

/// Time limit of each curl call, in seconds. It must stay below the command limit in main.rs,
/// so that curl reports its own error before the runner kills it.
pub const CURL_LIMIT: &str = "8";

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
    if let Some(marker) = gateway::open_marker(paths) {
        return Err(marker);
    }
    // Before each command: a grant that must refuse holds the lock for no command, and its checks cannot
    // stop the gateway of the active guest.
    let leases = lease::read_all(paths)
        .map_err(|e| format!("cannot read the lease directory {}: {e}", paths.leases.display()))?;
    if let Some((file, _)) = leases.first() {
        return Err(format!("a lease exists ({file}), and only one guest has access at a time; see `sparkpass list`"));
    }
    // With no lease, each notification marker is of an earlier lease. A marker of a lease with this name
    // would hide a message of the new lease (the markers hold the name only).
    let _ = fs::remove_file(&paths.model_down);
    let _ = fs::remove_file(&paths.gateway_down);
    let _ = fs::remove_file(&paths.revoke_failed);
    let model = model_name(runner, settings.model_port)?;
    // Only reconcile starts the gateway (the boot gate). Without this check, step 7 fails late.
    run_ok(runner, &["systemctl", "is-active", "--quiet", "caddy"])
        .map_err(|_| "the gateway is not running; run `sparkpass reconcile` and read its output".to_string())?;
    // The check of reconcile, through GATEWAY_CHECK_ADDRESS. With a wrong check address, the pass would
    // work until the next reconcile stops the gateway. A failed check stops the gateway, as in reconcile.
    check_gateway(paths, runner, &settings)?;
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
    // The clock after the lock and after the commands above (up to 7 commands, 70 seconds): neither shortens the TTL,
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

/// Step 1 and the health check of reconcile: the model must answer. Returns the model name.
pub fn model_name(runner: &dyn Runner, port: u16) -> Result<String, String> {
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
    // The monotonic time counts from a clock read right before systemd-run, not from the lease start: a
    // sync stall in step 2 must not make the timer longer (review of 2026-10-06).
    lease::create_end_timer(runner, lease, clock().max(lease.start))?;
    // 4. Token. It is not active yet.
    let token = gateway::new_token().map_err(|e| format!("cannot make a token: {e}"))?;
    // 5 and 6 are build phase 2: home image and workspace container.
    // 7. Activate the token. The model server is not touched. A sync stall in step 2 or a forward clock
    // step can pass the deadline before this point; when it passed before systemd-run, the monotonic time
    // of the timer is 0, and its revoke waits for the lock. The key must not go live after its end time.
    // The check looks forward only, so a backward step cannot make it fire.
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
    // the gateway stops (fail closed), and the next reconcile starts it with its own check, except after a
    // proven answer other than 401 to a wrong token at GATEWAY_CHECK_ADDRESS: that writes the gateway-open
    // marker (below).
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
        // An answer other than 401 through the public route is no proof by itself: a relay of the inbound
        // route (Tailscale Funnel) can give its own answer. The check of step 1 decides: a proven answer
        // there writes the marker (the gateway is open to all, and the revoke cannot close it), and a failed
        // request stops the gateway. A gateway that refuses the wrong token there stops too (fail closed),
        // with no marker: the public route does not reach it.
        Some((url, Ok(code))) => {
            let public = format!("the self-check with a wrong token through {url} got {code}, and it must get 401");
            check_gateway(paths, runner, settings).map_err(|e| format!("{public}; {e}"))?;
            return Err(format!(
                "{public}, but the gateway refuses the wrong token at {}: the inbound route does not reach this gateway, or it changes its answers; {}",
                settings.gateway_check_address,
                gateway::stop(runner)
            ));
        }
        Some((url, Err(e))) => return Err(format!("the self-check with a wrong token through {url} failed: {e}; {}", gateway::stop(runner))),
    }
    Ok(token)
}

/// Step 1, the decision of step 8, and the proof of reconcile after each start (TODO branch of 2026-10-06;
/// it extends the self-check of eng review D5): the public listener of this host refuses a wrong token.
/// `--connect-to` with an empty host and port sends each connection to GATEWAY_CHECK_ADDRESS (loopback, see
/// config.rs) on the port of PUBLIC_URL, never through the public route or DNS, and TLS still checks the
/// name of PUBLIC_URL. No part of the URL is parsed here. Each failure stops the gateway (fail closed), and
/// a proven answer other than 401 then writes the marker that keeps it stopped.
pub fn check_gateway(paths: &Paths, runner: &dyn Runner, settings: &Settings) -> Result<(), String> {
    let address = match settings.gateway_check_address {
        IpAddr::V6(address) => format!("[{address}]"),
        address => address.to_string(),
    };
    match wrong_token_answer(runner, &["--connect-to", &format!("::{address}:")], &settings.public_url) {
        None => Ok(()),
        Some((url, Ok(code))) => {
            let evidence = format!(
                "the gateway answered {code} through {url} at {address} to a request with a wrong token, and it must answer 401: the gateway does not enforce the token file; repair the import of the token file in the Caddyfile"
            );
            Err(gateway::mark_open(paths, runner, &evidence))
        }
        Some((url, Err(e))) => Err(format!("the check with a wrong token through {url} at {address} failed: {e}; {}", gateway::stop(runner))),
    }
}

/// Step 8 and the reconcile check: a GET of the model list and a POST to the route of the model, each
/// with a wrong token and with `extra` first. The URL and the answer of the first request that did not
/// get 401, or `None` when both got 401. Grant and reconcile send the same requests: after each start,
/// reconcile stops again a gateway that grant stopped (when both reach the same listener).
fn wrong_token_answer(runner: &dyn Runner, extra: &[&str], public_url: &str) -> Option<(String, Result<String, String>)> {
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
- The owner keeps the lease record (name, start, end) and the gateway access log (time, method, path, status, size; no client address).
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
    /// The check of step 1 through GATEWAY_CHECK_ADDRESS (the reconcile check).
    const CHECK_GET: &str = "curl -q --noproxy * -sS -o /dev/null -m 8 -w %{http_code} --connect-to ::127.0.0.1: -H Authorization: Bearer 0000000000000000000000000000000000000000000000000000000000000000 https://spark.example.net/v1/models";
    const CHECK_POST: &str = "curl -q --noproxy * -sS -o /dev/null -m 8 -w %{http_code} --connect-to ::127.0.0.1: -H Authorization: Bearer 0000000000000000000000000000000000000000000000000000000000000000 -H Content-Type: application/json -d {} https://spark.example.net/v1/chat/completions";
    const TIMER: &str = "systemd-run --collect --unit=sparkpass-end-bob-1709210396 --on-calendar=2024-02-29 12:39:56 UTC --on-active=300 --timer-property=AccuracySec=1s --timer-property=RemainAfterElapse=no --property=Type=oneshot --property=TimeoutStartSec=240 /usr/local/bin/sparkpass revoke bob --deadline 1709210396";
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

    // Added by the /ship review (2026-10-06, TODO batch 2).
    // Value: protects=an outage of a new lease with the name of an earlier lease gets its notification;
    // fails_when=grant keeps the outage markers of an earlier lease; why_new=reconcile compares the name
    // only, so a re-grant of the same name inherited the marker; seam=none
    #[test]
    fn grant_removes_the_outage_markers_of_an_earlier_lease() {
        let (paths, runner) = host();
        for marker in [&paths.model_down, &paths.gateway_down, &paths.revoke_failed] {
            fs::write(marker, "bob\n").unwrap();
        }
        assert!(grant(&paths, &runner, "bob", TTL, &|| NOW).is_ok());
        assert!(!paths.model_down.exists() && !paths.gateway_down.exists() && !paths.revoke_failed.exists());
    }

    // Added by the /ship review, pass 3: a refused grant keeps the outage markers of the active lease.
    #[test]
    fn grant_refused_for_an_existing_lease_keeps_the_outage_markers_of_that_lease() {
        for state in [State::Active, State::RevokeFailed] {
            let (paths, runner) = host();
            seed(&paths, "bob", END, state);
            for marker in [&paths.model_down, &paths.gateway_down, &paths.revoke_failed] {
                fs::write(marker, "bob\n").unwrap();
            }
            assert_refused(&paths, &runner, &paths.snapshot());
        }
    }

    // Added by the /ship review, Step 11 round 2 (2026-10-06).
    // Value: protects=the monotonic time of the end timer counts from a clock read right before systemd-run,
    // so a sync stall of the lease write cannot make the timer end after the deadline; fails_when=grant passes
    // the lease start; why_new=each grant test had a clock that does not move; seam=none
    #[test]
    fn end_timer_counts_from_the_clock_before_systemd_run() {
        let (paths, runner) = host();
        let reads = AtomicU64::new(0);
        // The first read sets the deadline; the lease write then takes 10 seconds.
        let clock = || NOW + if reads.fetch_add(1, Ordering::SeqCst) == 0 { 0 } else { 10 };
        assert!(grant(&paths, &runner, "bob", TTL, &clock).is_ok());
        assert_eq!(runner.count(&TIMER.replace("--on-active=300", "--on-active=290")), 1, "{:?}", runner.calls());
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
            // The log filter of gateway/Caddyfile deletes the client address (tests/gateway.sh, case "access log").
            "The owner keeps the lease record (name, start, end) and the gateway access log (time, method, path, status, size; no client address).",
            "no unlawful use, no attack on other systems, and no resale",
        ] {
            assert!(pass.contains(part), "{part:?} is not in:\n{pass}");
        }

        let self_check = format!("{SELF_CHECK}{token} {MODELS}");
        assert_eq!(
            runner.calls(),
            [HEALTH, CADDY_ACTIVE, CHECK_GET, CHECK_POST, FIREWALL, BINARY_CHECK, TIMER, CHECK_TIMER, RELOAD, &self_check, WRONG_GET, WRONG_POST]
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
        assert_eq!(argv[5], [config::BINARY, "revoke", "bob", "--deadline", "0"]);
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
            // Extended by the /ship test coverage audit (2026-10-06, TODO batch 2): no marker.
            // Value: protects=a failed check of the pass key is no proof of an open gateway, so it writes no marker;
            // fails_when=the marker write of step 8 moves to each failed self-check, and one 500 or timeout keeps the gateway stopped until the owner removes the marker;
            // why_new=only the proven wrong-token answers of step 8 had a marker assert; seam=none
            assert!(!paths.gateway_open.exists(), "{error}");
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
                // Extended by the /ship test coverage audit (2026-10-06, TODO batch 2): no marker.
                // Value: protects=a curl failure of a wrong-token request in step 8 writes no marker ("a curl failure never writes it");
                // fails_when=the Err branch of step 8 also calls mark_open, and one network fault keeps the gateway stopped until the owner removes the marker;
                // why_new=the marker asserts cover the step 8 answers and the curl failures of reconcile and grant step 1, not of step 8; seam=none
                assert!(!paths.gateway_open.exists(), "{error}");
                assert_revoked(&paths, &runner, result);
            }
        }
    }

    /// A healthy host whose check through GATEWAY_CHECK_ADDRESS (`probe`) gets `answer` from the reload of step 7
    /// on. Step 1 still passes: with the deny-all rule, each request gets 401.
    fn host_with_a_check_answer_after_the_reload(probe: &'static str, answer: Result<Output, RunError>) -> (Paths, Arc<FakeRunner>) {
        let (paths, runner) = (Paths::temp(), Arc::new(FakeRunner::healthy()));
        runner.hook({
            // Weak: the hook lives in the runner.
            let runner = Arc::downgrade(&runner);
            move |argv| {
                if argv.join(" ") == RELOAD
                    && let Some(runner) = runner.upgrade()
                {
                    runner.on(probe, answer.clone());
                }
            }
        });
        (paths, runner)
    }

    // A gateway that does not enforce the token file is open to all, and a revoke cannot close it. The check
    // through GATEWAY_CHECK_ADDRESS confirms the answer of the public route (P1 item of 2026-10-07).
    #[test]
    fn wrong_token_that_is_not_refused_stops_the_gateway_before_the_revoke() {
        for (request, probe, url, runs) in [(WRONG_GET, CHECK_GET, MODELS, 2), (WRONG_POST, CHECK_POST, CHAT, 3)] {
            for code in ["200", "404", "204", "302", "500", ""] {
                let (paths, runner) = host_with_a_check_answer_after_the_reload(probe, output(0, code));
                runner.on(request, output(0, code));
                let result = grant(&paths, &*runner, "bob", TTL, &|| NOW);
                let error = result.as_ref().unwrap_err();
                for part in [
                    &format!("the self-check with a wrong token through {url} got {code}, and it must get 401; "),
                    &format!("the gateway answered {code} through {url} at 127.0.0.1 to a request with a wrong token, and it must answer 401"),
                    "the gateway does not enforce the token file; repair the import of the token file in the Caddyfile; the gateway is stopped;",
                    "the gateway is stopped; each reconcile run stops the gateway until you repair the Caddyfile and remove",
                ] {
                    assert!(error.contains(part), "{part:?} is not in: {error}");
                }
                // The marker keeps the gateway stopped and holds the evidence of the check address.
                let marker = fs::read_to_string(&paths.gateway_open).unwrap();
                assert!(marker.contains(&format!("answered {code} through {url} at 127.0.0.1")), "{marker}");
                assert_eq!(runner.count(SELF_CHECK), runs);
                // One stop, and then the revoke: try-restart has no effect on a stopped gateway.
                assert_eq!(runner.count(STOP_CADDY), 1);
                let calls = runner.calls();
                assert!(calls.ends_with(&[probe, STOP_CADDY, RESTART, STOP_TIMER, CHECK_TIMER].map(String::from)), "{calls:?}");
                assert_revoked(&paths, &runner, result);
            }
        }
    }

    // Added for the P1 item "Prove the gateway step on the units" (2026-10-07).
    // Value: protects=an answer of the inbound route alone (a relay of Tailscale Funnel answers with its own
    // error) writes no marker, and the grant still fails closed; fails_when=step 8 writes the marker for a
    // public answer that the check address does not confirm, or the gateway stays up; why_new=step 8 trusted
    // the public answer; seam=none
    #[test]
    fn wrong_token_answer_of_the_public_route_alone_stops_the_gateway_with_no_marker() {
        for (request, url) in [(WRONG_GET, MODELS), (WRONG_POST, CHAT)] {
            for code in ["502", "530", "200", ""] {
                let (paths, runner) = host();
                runner.on(request, output(0, code));
                let result = grant(&paths, &runner, "bob", TTL, &|| NOW);
                let error = result.as_ref().unwrap_err();
                let text = format!(
                    "the self-check with a wrong token through {url} got {code}, and it must get 401, but the gateway refuses the wrong token at 127.0.0.1: the inbound route does not reach this gateway, or it changes its answers; the gateway is stopped"
                );
                assert!(error.contains(&text), "{error}");
                assert!(!paths.gateway_open.exists(), "{error}");
                // The check of step 1 again (both requests get 401), the stop, then the revoke.
                assert_eq!(runner.count(STOP_CADDY), 1);
                assert_eq!(runner.count(CHECK_GET), 2);
                let calls = runner.calls();
                assert!(calls.ends_with(&[CHECK_GET, CHECK_POST, STOP_CADDY, RESTART, STOP_TIMER, CHECK_TIMER].map(String::from)), "{calls:?}");
                assert_revoked(&paths, &runner, result);
            }
        }
    }

    // Added for the P1 item "Prove the gateway step on the units" (2026-10-07).
    // Value: protects=a failed check through the check address after an answer of the public route is no
    // proof either: the gateway stops, with no marker; fails_when=the Err of check_gateway in step 8 writes the
    // marker or keeps the gateway up; why_new=the confirmation of step 8 is new; seam=none
    #[test]
    fn wrong_token_answer_of_the_public_route_and_a_failed_check_stop_the_gateway_with_no_marker() {
        for (check, text) in [(output(7, "000"), "curl exit code 7"), (Err(RunError::Timeout(Duration::from_secs(10))), "curl: no result after 10s")] {
            let (paths, runner) = host_with_a_check_answer_after_the_reload(CHECK_GET, check);
            runner.on(WRONG_GET, output(0, "200"));
            let result = grant(&paths, &*runner, "bob", TTL, &|| NOW);
            let error = result.as_ref().unwrap_err();
            let want = format!(
                "the self-check with a wrong token through {MODELS} got 200, and it must get 401; the check with a wrong token through {MODELS} at 127.0.0.1 failed: {text}; the gateway is stopped"
            );
            assert!(error.contains(&want), "{error}");
            assert!(!paths.gateway_open.exists(), "{error}");
            assert_eq!(runner.count(STOP_CADDY), 1);
            let calls = runner.calls();
            assert!(calls.ends_with(&[CHECK_GET, STOP_CADDY, RESTART, STOP_TIMER, CHECK_TIMER].map(String::from)), "{calls:?}");
            assert_revoked(&paths, &runner, result);
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
                // No command: the checks of step 1 cannot stop the gateway of the active guest.
                assert_eq!(runner.calls(), [] as [&str; 0]);
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

        // A check address that is not loopback, for example the other Spark: no command runs.
        let (paths, runner) = host();
        fs::write(&paths.config, "PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\nGATEWAY_CHECK_ADDRESS=192.168.1.20\n").unwrap();
        assert_refused(&paths, &runner, &paths.snapshot());
        assert_eq!(runner.calls(), [] as [&str; 0]);
        let error = grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap_err();
        assert!(error.contains("GATEWAY_CHECK_ADDRESS must be a loopback IP address"), "{error}");
    }

    #[test]
    fn grant_refuses_when_the_firewall_script_fails() {
        for firewall in [output(1, ""), Err(RunError::Spawn("No such file or directory".into()))] {
            let (paths, runner) = host();
            runner.on(FIREWALL, firewall);
            assert_refused(&paths, &runner, &paths.snapshot());
            assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE, CHECK_GET, CHECK_POST, FIREWALL]);
        }
    }

    #[test]
    fn grant_refuses_when_the_end_timer_binary_does_not_run() {
        // Exit code 2: an old build that refuses `--deadline` (a usage error). 126: not executable.
        for check in [output(2, ""), output(1, ""), output(126, ""), Err(RunError::Spawn("No such file or directory".into()))] {
            let (paths, runner) = host();
            runner.on(BINARY_CHECK, check);
            assert_refused(&paths, &runner, &paths.snapshot());
            assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE, CHECK_GET, CHECK_POST, FIREWALL, BINARY_CHECK]);
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
        assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE, CHECK_GET, CHECK_POST, FIREWALL, BINARY_CHECK]);
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
            assert_eq!(calls[..7], [HEALTH, CADDY_ACTIVE, CHECK_GET, CHECK_POST, FIREWALL, RESTART, BINARY_CHECK], "{text:?}");
            assert!(gateway::is_rule_of(&paths, "bob"));
            assert_ne!(fs::read_to_string(&paths.token).unwrap(), text);
        }
        // The close fails: the gateway stops, and grant refuses with no lease.
        let (paths, runner) = host();
        fs::write(&paths.token, gateway::rule(Some(("bob", "ab")))).unwrap();
        runner.exit(RESTART, 1);
        let error = grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap_err();
        assert!(error.contains("the token file held a rule with no lease, and the close failed") && error.ends_with("the gateway is stopped"), "{error}");
        assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE, CHECK_GET, CHECK_POST, FIREWALL, RESTART, STOP_CADDY]);
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
    }

    #[test]
    fn grant_refuses_a_deadline_that_does_not_fit_after_the_lock() {
        let (paths, runner) = host();
        let before = paths.snapshot();
        assert_eq!(grant(&paths, &runner, "bob", 60, &|| u64::MAX - 59), Err("the TTL is too large".into()));
        // The clock is read after the checks of step 1, and they write nothing.
        assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE, CHECK_GET, CHECK_POST, FIREWALL, BINARY_CHECK]);
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

    #[test]
    fn grant_refuses_while_the_gateway_is_marked_open() {
        let (paths, runner) = host();
        fs::write(&paths.gateway_open, "the gateway answered 200 through https://spark.example.net/v1/models\n").unwrap();
        let error = grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap_err();
        assert!(error.contains("the gateway was proven open earlier") && error.contains("answered 200"), "{error}");
        assert_eq!(runner.calls(), [] as [&str; 0]);
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
    }

    #[test]
    fn failed_check_through_the_check_address_stops_the_gateway_and_refuses() {
        // A proven answer other than 401 writes the marker; a curl failure writes none.
        for (answer, marked) in [(output(0, "200"), true), (output(0, "404"), true), (output(7, "000"), false)] {
            let (paths, runner) = host();
            runner.on(CHECK_GET, answer);
            let before = paths.snapshot();
            let error = grant(&paths, &runner, "bob", TTL, &|| NOW).unwrap_err();
            assert!(error.contains("at 127.0.0.1") && error.contains("the gateway is stopped"), "{error}");
            assert_eq!(runner.calls(), [HEALTH, CADDY_ACTIVE, CHECK_GET, STOP_CADDY]);
            assert_eq!(paths.gateway_open.exists(), marked, "{error}");
            if !marked {
                assert_eq!(paths.snapshot(), before);
            }
        }
    }
}
