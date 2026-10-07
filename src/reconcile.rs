//! `sparkpass reconcile` (at boot and each 5 minutes). Diagram from the design document:
//!
//! ```text
//! flock, then read the clock
//!  1 firewall rules ── fail ──▶ stop workspace, stop Caddy, exit non-zero
//!    unreadable lease file ──▶ stop Caddy and workspace, exit non-zero (D7)
//!  2 lease overdue or REVOKE-FAILED ──▶ revoke
//!    token file not deny-all and no lease ──▶ close the gateway
//!    token file not the rule of the active lease ──▶ revoke that lease (its key is dead)
//!    settings file missing or bad ──▶ stop Caddy, exit non-zero
//!  3 lease still active ──▶ attach image, create end timer, start workspace
//!  4 read the clock again, revoke each lease that is overdue now
//!    gateway-open marker ──▶ stop Caddy, exit non-zero
//!    a failed revoke or close in 2 or 4, or no end timer in 3 for a lease that ends before the next run
//!      ──▶ stop Caddy, exit non-zero (the cut is not proven)
//!    any other failure (an end timer in 3) ──▶ do not start Caddy; a Caddy that runs gets the check below
//!      ── fail ──▶ stop Caddy; a Caddy in an unknown state ──▶ stop Caddy
//!    no failure ──▶ start Caddy ── fail ──▶ stop Caddy, exit non-zero
//!    a wrong token (GET and POST) to the public listener at GATEWAY_CHECK_ADDRESS gets no 401 ──▶ stop Caddy,
//!      exit non-zero (D5); a proven answer other than 401 ──▶ also write gateway-open
//!    success with an active lease ──▶ model check (one notification at the start and at the end of an outage)
//!    gateway stopped or not started with an active lease ──▶ one notification; the next successful start ──▶ one more
//! ```
//!
//! Build phase 1 has no workspace and no home image. The step order is the safety property:
//! only this command starts the gateway, only after each overdue lease is revoked, and only with
//! the proof that the gateway refuses a wrong token.

use crate::config::{self, Paths, Settings};
use crate::gateway;
use crate::grant::{check_gateway, model_name};
use crate::lease::{self, Lease, State};
use crate::notify;
use crate::revoke::revoke;
use crate::runner::{Runner, exit_text, run_ok};
use std::cell::Cell;
use std::fs;
use std::io::{self, Write};

/// The latest start of the next run, in seconds: pass-reconcile.timer starts a run each 5 minutes, and a
/// run can take up to TimeoutStartSec of pass-reconcile.service (180 s) before its revoke.
const NEXT_RUN: u64 = 300 + 180;

pub fn reconcile(paths: &Paths, runner: &dyn Runner, clock: &dyn Fn() -> u64) -> Result<(), String> {
    // True when a run failed but the gateway still runs with its proof (a failed step, see step 4).
    let runs = Cell::new(false);
    let result = steps(paths, runner, clock, &runs);
    match &result {
        Ok(()) => gateway_up(paths, runner),
        Err(e) if !runs.get() => gateway_down(paths, runner, e),
        Err(_) => {}
    }
    result
}

fn steps(paths: &Paths, runner: &dyn Runner, clock: &dyn Fn() -> u64, runs: &Cell<bool>) -> Result<(), String> {
    let _lock = match paths.lock() {
        Ok(lock) => lock,
        Err(e) => return fail_closed(runner, format!("cannot take the lock {}: {e}", paths.lock.display())),
    };
    // The clock never goes back within one run: a lease that one read sees as overdue stays overdue, also
    // after a backward step of the system clock. Step 3 counts on this.
    let latest = Cell::new(0);
    let clock = || {
        let t = clock().max(latest.get());
        latest.set(t);
        t
    };
    // After the lock: a lease whose deadline passed during the wait is overdue.
    let now = clock();
    // 1. Firewall rules.
    if let Err(e) = run_ok(runner, &[config::FIREWALL]) {
        return fail_closed(runner, format!("the firewall rules did not load: {e}"));
    }
    // An unreadable lease can be an overdue lease (eng review D7).
    let leases = match lease::read_all(paths) {
        Ok(all) => all
            .into_iter()
            .map(|(_, lease)| lease)
            .collect::<Result<Vec<Lease>, String>>()
            .map_err(|e| format!("unreadable lease file {e}")),
        Err(e) => Err(format!("cannot read the lease directory {}: {e}", paths.leases.display())),
    };
    let leases = match leases {
        Ok(leases) => leases,
        Err(e) => return fail_closed(runner, e),
    };
    let (ended, mut active): (Vec<&Lease>, Vec<&Lease>) = leases
        .iter()
        .partition(|lease| lease.deadline <= now || lease.state == State::RevokeFailed);
    let mut failed = Vec::new();
    // A failed revoke or close (the access cut is not proven), or an active lease with no end timer near
    // its end: the gateway must stop (see step 4).
    let mut must_stop = false;
    // 2. Revoke each lease that is overdue or in state revoke-failed.
    for lease in ended {
        // The end time of the record is the time of the revoke: an earlier revoke can have taken 30 seconds.
        if let Err(e) = revoke(paths, runner, &lease.name, clock(), false) {
            failed.push(e);
            must_stop = true;
        }
    }
    // The token file gate. It runs before the settings read and step 3, so that a failure there cannot
    // skip it while a gateway runs.
    // With no lease, the token file must be the deny-all rule. A token with no lease has no end: it
    // stays, for example, after the owner removed an unreadable lease file by hand. An empty or cut
    // file has no token check: a power cut in `gateway::write_rule` leaves it.
    if active.is_empty() {
        if !gateway::is_deny_all(paths) {
            // Not eprintln!: it panics when the journal stream is gone, and the close below must run.
            let _ = writeln!(io::stderr(), "sparkpass: reconcile: the token file holds a rule with no lease; closing the gateway");
            if let Err(e) = gateway::close(paths, runner) {
                failed.push(e);
                must_stop = true;
            }
        }
    } else if !active.iter().any(|lease| gateway::is_rule_of(paths, &lease.name)) {
        // With an active lease, the file must be its complete rule. No grant runs under this lock, so
        // each other content (deny-all included: a grant or a revoke that stopped half way) is a dead
        // key. The revoke closes the gateway (revoke steps 1 and 2), records the history, and frees the
        // slot. The lease is not active after it, so step 3 gives it no timer.
        for lease in active.drain(..) {
            let _ = writeln!(
                io::stderr(),
                "sparkpass: reconcile: the token file is not the rule of lease {}; revoking it, because its key is dead",
                lease.name
            );
            if let Err(e) = revoke(paths, runner, &lease.name, clock(), false) {
                failed.push(e);
                must_stop = true;
            }
        }
    }
    // The check after the start in step 4 needs the settings file: with no proof, no gateway. An access
    // cut needs no settings, so step 2 and the gate run first.
    let settings = match config::read_settings(paths) {
        Ok(settings) => settings,
        Err(e) => {
            failed.push(e);
            return fail_closed(runner, failed.join("; "));
        }
    };
    // 3. A reboot removes transient timers: create the end timer again if it does not exist.
    for lease in &active {
        let timer = match lease::end_timer_exists(runner, lease) {
            Ok(true) => Ok(()),
            // The clock again: the commands above can take 20 seconds, and the timer counts from now. The
            // production clock (main.rs steady_clock) never falls behind the time since its first read, so a
            // backward step does not make the timer longer. A deadline that passed in the meantime needs no
            // timer: step 4 revokes that lease.
            Ok(false) => match clock() {
                later if lease.deadline <= later => Ok(()),
                later => lease::create_end_timer(runner, lease, later),
            },
            Err(e) => Err(e),
        };
        if let Err(e) = timer {
            failed.push(e);
            // With no end timer, only the next run revokes the lease: a deadline before that run would
            // leave the key live past its end (owner decision D15 of the review of 2026-10-06).
            if lease.deadline <= clock().saturating_add(NEXT_RUN) {
                must_stop = true;
            }
        }
    }
    // 4. The clock again, right before the start: a deadline can pass during the steps above.
    let now = clock();
    for lease in active.iter().filter(|lease| lease.deadline <= now) {
        if let Err(e) = revoke(paths, runner, &lease.name, now, false) {
            failed.push(e);
            must_stop = true;
        }
    }
    // A gateway proven open stays stopped until the owner repairs the Caddyfile and removes the marker.
    if let Some(marker) = gateway::open_marker(paths) {
        failed.push(marker);
        return fail_closed(runner, failed.join("; "));
    }
    // After a failure: no start. After a failure that is not an access cut (an end timer of step 3), a
    // gateway that runs still gets its proof, because a failure that repeats on each run must not end the
    // only periodic proof; a failed proof stops it (check_gateway). Otherwise a gateway that runs stays:
    // each revoke and close of this run succeeded. Exit code 3 is "not active"; each other answer (a
    // time-out, an error of systemctl) leaves the state unknown: stop.
    if !failed.is_empty() {
        // A failed revoke or close leaves the access cut unproven: Caddy can still hold the old key in
        // memory (a failed deny-all write or restart, and a failed stop), and a check with a wrong key
        // cannot see that key. Stop the gateway; each run tries the stop again. No active guest loses
        // access: a revoked lease has ended, and grant allows one lease at a time. Also stop for an
        // active lease with no end timer that ends before the next run (step 3).
        if must_stop {
            return fail_closed(runner, failed.join("; "));
        }
        match runner.run(&["systemctl", "is-active", "--quiet", "caddy"]) {
            Ok(out) if out.code == Some(3) => {}
            Ok(out) if out.code == Some(0) => {
                if let Err(e) = check_gateway(paths, runner, &settings) {
                    failed.push(e);
                    return Err(failed.join("; "));
                }
                runs.set(true);
                return Err(format!("{}; the gateway runs with its proof, and it was not started again", failed.join("; ")));
            }
            other => {
                failed.push(format!("the state of the gateway is unknown: {}", match other {
                    Ok(out) => format!("`systemctl is-active caddy` {}", exit_text(out.code)),
                    Err(e) => format!("`systemctl is-active caddy`: {e}"),
                }));
                return fail_closed(runner, failed.join("; "));
            }
        }
        return Err(format!("{}; the gateway was not started", failed.join("; ")));
    }
    // Start the gateway (no effect if it runs). A start that failed or timed out can still complete in
    // systemd, and that gateway has no proof: stop it.
    // ponytail: one check, right after the start. A Caddy that still waits for its first ACME certificate
    // (a first install, or a host that was off past the end of its certificate) fails the TLS check, and
    // each run stops it again. Upgrade: repeat the check for the time of an ACME order. Until then, the
    // owner starts Caddy by hand, waits for the certificate, and runs reconcile.
    if let Err(e) = run_ok(runner, &["systemctl", "start", "caddy"]) {
        return fail_closed(runner, e);
    }
    check_gateway(paths, runner, &settings)?;
    match active.iter().find(|lease| lease.deadline > now) {
        Some(lease) => check_model(paths, runner, &settings, &lease.name),
        // No lease: an outage marker of an ended lease has no use.
        None => {
            let _ = fs::remove_file(&paths.model_down);
        }
    }
    Ok(())
}

/// During a lease, the model must answer (owner decision of 2026-10-06). One outage sends one notification
/// (the marker), and its end sends one more. Nothing else changes: the guest gets 503 meanwhile.
fn check_model(paths: &Paths, runner: &dyn Runner, settings: &Settings, name: &str) {
    // The marker of this lease only: a marker that an earlier lease left must not hide this outage.
    let down = fs::read_to_string(&paths.model_down).is_ok_and(|text| text.trim() == name);
    match model_name(runner, settings.model_port) {
        // The marker goes after a sent notification only, as below: a failed send is tried again.
        Ok(_) if down => {
            if notify::send(paths, runner, &format!("sparkpass: the model endpoint answers again during the lease of {name}")) {
                let _ = fs::remove_file(&paths.model_down);
            }
        }
        Ok(_) => {}
        Err(e) => {
            let _ = writeln!(io::stderr(), "sparkpass: reconcile: {e}, during the lease of {name}");
            // The marker after a sent notification only: a failed send is tried again on the next run.
            if !down && notify::send(paths, runner, &format!("sparkpass: {e}, during the lease of {name}; the guest gets 503 until the model runs again")) {
                let _ = fs::write(&paths.model_down, format!("{name}\n"));
            }
        }
    }
}

/// The name of a lease that is active after the run, or the file of an unreadable lease, for the
/// notifications of the gateway. A REVOKE-FAILED lease sent its own notification.
fn active_lease(paths: &Paths) -> Option<String> {
    lease::read_all(paths).ok()?.into_iter().find_map(|(file, lease)| match lease {
        Ok(lease) => (lease.state == State::Active).then_some(lease.name),
        Err(_) => Some(file.strip_suffix(".json").unwrap_or(&file).to_string()),
    })
}

/// During a lease, a gateway that reconcile stopped or did not start gives the guest no access, also for
/// hours (owner decision of 2026-10-06, review D3): one notification for each outage (the marker holds the
/// lease name, as `model-down` does). Also with gateway-open: mark_open sends one message, and a failed send
/// of it is not tried again.
fn gateway_down(paths: &Paths, runner: &dyn Runner, error: &str) {
    let Some(name) = active_lease(paths) else {
        return;
    };
    if fs::read_to_string(&paths.gateway_down).is_ok_and(|text| text.trim() == name) {
        return;
    }
    // The marker after a sent notification only: a failed send is tried again on the next run.
    if notify::send(paths, runner, &format!("sparkpass: the gateway does not run during the lease of {name}, so the guest has no access; reconcile tries again each 5 minutes: {error}")) {
        let _ = fs::write(&paths.gateway_down, format!("{name}\n"));
    }
}

/// The end of the outage of `gateway_down`: one more notification while that lease is still active. The
/// marker goes after a sent notification only (a failed send is tried again), or at once with no such lease.
fn gateway_up(paths: &Paths, runner: &dyn Runner) {
    let Ok(text) = fs::read_to_string(&paths.gateway_down) else {
        return;
    };
    let name = text.trim();
    if !active_lease(paths).is_some_and(|lease| lease == name)
        || notify::send(paths, runner, &format!("sparkpass: the gateway runs again during the lease of {name}"))
    {
        let _ = fs::remove_file(&paths.gateway_down);
    }
}

/// Fail closed: the state of the gateway rules is unknown, so the gateway stops.
fn fail_closed(runner: &dyn Runner, cause: String) -> Result<(), String> {
    Err(format!("{cause}; {}", gateway::stop(runner)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::{files, seed};
    use crate::runner::fake::{FakeRunner, output};
    use crate::runner::{Output, RunError};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    const NOW: u64 = 1_500;
    const FIREWALL: &str = config::FIREWALL;
    const START: &str = "systemctl start caddy";
    const STOP: &str = "systemctl stop caddy";
    const RESTART: &str = "systemctl try-restart caddy";
    const CADDY_ACTIVE: &str = "systemctl is-active --quiet caddy";
    /// The health check of the model during a lease, after the gateway check.
    const HEALTH: &str = "curl -q --noproxy * -fsS -m 8 http://127.0.0.1:8000/v1/models";
    const REVOKE_FAILED: &str = "the revoke of bob is not complete (state revoke-failed)";
    /// The check with a wrong token after the start, through the check address of `Paths::temp`.
    const PROBE: &str = "curl -q --noproxy * -sS -o /dev/null -m 8 -w %{http_code} --connect-to ::127.0.0.1: -H Authorization: Bearer 0000000000000000000000000000000000000000000000000000000000000000 https://spark.example.net/v1/models";
    /// The second check with a wrong token: a POST to the route of the model.
    const PROBE_POST: &str = "curl -q --noproxy * -sS -o /dev/null -m 8 -w %{http_code} --connect-to ::127.0.0.1: -H Authorization: Bearer 0000000000000000000000000000000000000000000000000000000000000000 -H Content-Type: application/json -d {} https://spark.example.net/v1/chat/completions";

    fn stop_timer(deadline: u64) -> String {
        format!("systemctl stop sparkpass-end-bob-{deadline}.timer")
    }

    fn check_timer(deadline: u64) -> String {
        format!("systemctl is-active --quiet sparkpass-end-bob-{deadline}.timer")
    }

    fn create_timer(deadline: u64) -> String {
        format!("systemd-run --collect --unit=sparkpass-end-bob-{deadline}")
    }

    fn hang() -> Result<Output, RunError> {
        Err(RunError::Timeout(Duration::from_secs(10)))
    }

    fn state(paths: &Paths) -> State {
        lease::read(paths, "bob").unwrap().unwrap().state
    }

    /// The complete rule of lease bob in the token file: the key of bob is live.
    fn write_rule_of_bob(paths: &Paths) {
        gateway::write_rule(paths, &gateway::rule(Some(("bob", &"ab".repeat(32))))).unwrap();
    }

    fn end_of_record(paths: &Paths) -> serde_json::Value {
        let record = fs::read_to_string(paths.history.join("bob-1000.json")).unwrap();
        serde_json::from_str::<serde_json::Value>(&record).unwrap()["end"].clone()
    }

    #[test]
    fn no_lease_starts_the_gateway() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        assert_eq!(runner.calls(), [FIREWALL, START, PROBE, PROBE_POST]);
    }

    #[test]
    fn failed_gateway_start_stops_the_gateway() {
        // A start that timed out can still complete in systemd, with no check after it.
        for start in [output(1, ""), hang()] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            runner.on(START, start);
            let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
            assert!(error.ends_with("; the gateway is stopped"), "{error}");
            assert_eq!(runner.calls(), [FIREWALL, START, STOP]);
        }
    }

    #[test]
    fn check_with_a_wrong_token_goes_to_the_check_address_with_the_name_of_the_public_url() {
        // An IPv6 literal and a user part in PUBLIC_URL need no parse: curl takes the host and the port from the URL.
        for (settings, connect, url) in [
            ("PUBLIC_URL=https://spark.example.net/\nGATEWAY_CHECK_ADDRESS=127.0.0.1\n", "::127.0.0.1:", "https://spark.example.net/v1/models"),
            ("PUBLIC_URL=https://10.0.0.5:8443\nGATEWAY_CHECK_ADDRESS=::1\n", "::[::1]:", "https://10.0.0.5:8443/v1/models"),
            ("PUBLIC_URL=https://spark.example.net:8443/api\nGATEWAY_CHECK_ADDRESS=192.168.1.20\n", "::192.168.1.20:", "https://spark.example.net:8443/api/v1/models"),
            ("PUBLIC_URL=https://[2001:db8::5]:8443\nGATEWAY_CHECK_ADDRESS=127.0.0.1\n", "::127.0.0.1:", "https://[2001:db8::5]:8443/v1/models"),
            ("PUBLIC_URL=https://u@spark.example.net\nGATEWAY_CHECK_ADDRESS=127.0.0.1\n", "::127.0.0.1:", "https://u@spark.example.net/v1/models"),
        ] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            fs::write(&paths.config, format!("MODEL_PORT=8000\n{settings}")).unwrap();
            assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()), "{settings}");
            let argv = runner.argv();
            let wrong = format!("Authorization: Bearer {}", "0".repeat(64));
            let head = ["curl", "-q", "--noproxy", "*", "-sS", "-o", "/dev/null", "-m", "8", "-w", "%{http_code}", "--connect-to", connect, "-H", &wrong];
            let chat = url.replace("/v1/models", "/v1/chat/completions");
            assert_eq!(
                argv[argv.len() - 2..],
                [[&head[..], &[url]].concat(), [&head[..], &["-H", "Content-Type: application/json", "-d", "{}", &chat]].concat()]
            );
        }
    }


    #[test]
    fn wrong_token_that_is_not_refused_after_the_start_stops_the_gateway() {
        for (probe, answer, text) in [
            (PROBE, output(0, "200"), "the gateway answered 200 through https://spark.example.net/v1/models at 127.0.0.1 to a request with a wrong token, and it must answer 401"),
            (PROBE, output(0, "404"), "the gateway answered 404 through"),
            (PROBE, output(0, ""), "the gateway answered  through"),
            (PROBE, output(7, "000"), "the check with a wrong token through https://spark.example.net/v1/models at 127.0.0.1 failed: curl exit code 7"),
            (PROBE, output(60, "000"), "failed: curl exit code 60"),
            (PROBE, hang(), "failed: curl: no result after 10s"),
            // The list route refuses the wrong token, but the route of the model does not: grant stops
            // such a gateway, so reconcile must not start it again.
            (PROBE_POST, output(0, "200"), "the gateway answered 200 through https://spark.example.net/v1/chat/completions at 127.0.0.1"),
            (PROBE_POST, hang(), "the check with a wrong token through https://spark.example.net/v1/chat/completions at 127.0.0.1 failed: curl: no result after 10s"),
        ] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", 2_000, State::Active);
            write_rule_of_bob(&paths);
            runner.exit(&check_timer(2_000), 0);
            runner.on(probe, answer);
            let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
            assert!(error.contains(text) && error.contains("; the gateway is stopped"), "{error}");
            let probes: &[&str] = if probe == PROBE { &[PROBE] } else { &[PROBE, PROBE_POST] };
            assert_eq!(runner.calls(), [&[FIREWALL, &check_timer(2_000), START][..], probes, &[STOP]].concat());
            assert!(!error.contains(&"ab".repeat(32)), "{error}");
        }
    }

    #[test]
    fn token_file_gate_closes_the_gateway_when_stderr_is_broken() {
        // eprintln! panics when the journal stream is gone, and the close after the message would not run.
        // libtest captures eprintln!, so the test starts itself again with stderr on /dev/full.
        const GUARD: &str = "SPARKPASS_TEST_BROKEN_STDERR";
        if std::env::var_os(GUARD).is_none() {
            let full = fs::File::options().write(true).open("/dev/full").unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "reconcile::tests::token_file_gate_closes_the_gateway_when_stderr_is_broken", "--nocapture"])
                .env(GUARD, "1")
                .stdout(std::process::Stdio::null())
                .stderr(full)
                .status()
                .unwrap();
            assert!(status.success(), "{status:?}");
            return;
        }
        // A rule with no lease: the gateway closes.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        gateway::write_rule(&paths, &gateway::rule(Some(("bob", "abc")))).unwrap();
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        assert!(gateway::is_deny_all(&paths));
        // An active lease with a dead key (an empty token file): the lease is revoked.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        fs::write(&paths.token, "").unwrap();
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        assert_eq!(lease::read(&paths, "bob"), Ok(None));
        assert!(gateway::is_deny_all(&paths));
    }

    #[test]
    fn missing_settings_file_stops_the_gateway_also_after_a_failed_revoke() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 1_000, State::Active);
        // The revoke of the overdue lease fails: its end timer stays active.
        runner.exit(&check_timer(1_000), 0);
        fs::remove_file(&paths.config).unwrap();
        let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
        assert!(error.contains("cannot read the settings file") && error.ends_with("; the gateway is stopped"), "{error}");
        assert!(error.contains(REVOKE_FAILED) && error.contains("is active after the stop"), "{error}");
        assert_eq!(runner.calls(), [FIREWALL, RESTART, &stop_timer(1_000), &check_timer(1_000), STOP]);
        assert_eq!(state(&paths), State::RevokeFailed);
    }

    #[test]
    fn missing_or_bad_settings_file_revokes_overdue_leases_and_stops_the_gateway() {
        for settings in [None, Some("PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\n"), Some("PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\nGATEWAY_CHECK_ADDRESS=localhost\n")] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", 1_000, State::Active);
            write_rule_of_bob(&paths);
            match settings {
                None => fs::remove_file(&paths.config).unwrap(),
                Some(text) => fs::write(&paths.config, text).unwrap(),
            }
            let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
            // The access cut needs no settings.
            assert_eq!(runner.calls(), [FIREWALL, RESTART, &stop_timer(1_000), &check_timer(1_000), STOP]);
            assert!(gateway::is_deny_all(&paths));
            assert_eq!(files(&paths.leases), [] as [&str; 0]);
            assert_eq!(files(&paths.history), ["bob-1000.json"]);
            // The error names the settings problem.
            let file = paths.config.display().to_string();
            assert!(error.contains(&file) && error.ends_with("; the gateway is stopped"), "{error}");
            if settings.is_some() {
                assert!(error.contains("GATEWAY_CHECK_ADDRESS"), "{error}");
            }
        }

        // The token file gate needs no settings either: the dead key of an active lease is revoked.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        fs::write(&paths.token, "").unwrap();
        fs::remove_file(&paths.config).unwrap();
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        assert_eq!(runner.calls(), [FIREWALL, RESTART, &stop_timer(2_000), &check_timer(2_000), STOP]);
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
    }

    #[test]
    fn lease_whose_deadline_passes_during_the_lock_wait_is_revoked_and_gets_no_timer() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        write_rule_of_bob(&paths);
        let clock = AtomicU64::new(NOW);
        std::thread::scope(|scope| {
            // In the scope: a failed assert drops the lock, and the test fails and does not hang.
            let lock = paths.lock().unwrap();
            let reconciler = scope.spawn(|| reconcile(&paths, &runner, &|| clock.load(Ordering::SeqCst)));
            std::thread::sleep(Duration::from_millis(200));
            assert!(!reconciler.is_finished());
            // The wait for the lock passes the deadline.
            clock.store(2_000, Ordering::SeqCst);
            drop(lock);
            assert_eq!(reconciler.join().unwrap(), Ok(()));
        });
        assert_eq!(runner.calls(), [FIREWALL, RESTART, &stop_timer(2_000), &check_timer(2_000), START, PROBE, PROBE_POST]);
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
        assert_eq!(end_of_record(&paths), 2_000);
    }

    #[test]
    fn deadline_that_passes_before_the_gateway_start_is_revoked_before_the_start() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        write_rule_of_bob(&paths);
        // The first read is after the lock, and the second one before the end timer. The steps after it
        // take the rest of the lease, and the third read is right before the start.
        let reads = AtomicU64::new(0);
        let clock = || if reads.fetch_add(1, Ordering::SeqCst) < 2 { NOW } else { 2_000 };
        assert_eq!(reconcile(&paths, &runner, &clock), Ok(()));
        let calls = runner.calls();
        assert_eq!(runner.count(&create_timer(2_000)), 1, "{calls:?}");
        assert!(calls.ends_with(&[RESTART, &stop_timer(2_000), &check_timer(2_000), START, PROBE, PROBE_POST].map(String::from)), "{calls:?}");
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
        assert_eq!(end_of_record(&paths), 2_000);
        assert!(gateway::is_deny_all(&paths));

        // The deadline passes before the end timer: no timer, and step 4 revokes the lease.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        write_rule_of_bob(&paths);
        let reads = AtomicU64::new(0);
        let clock = || if reads.fetch_add(1, Ordering::SeqCst) == 0 { NOW } else { 2_000 };
        assert_eq!(reconcile(&paths, &runner, &clock), Ok(()));
        assert_eq!(
            runner.calls(),
            [FIREWALL, &check_timer(2_000), RESTART, &stop_timer(2_000), &check_timer(2_000), START, PROBE, PROBE_POST]
        );
        assert_eq!(files(&paths.leases), [] as [&str; 0]);

        // The same, and then the clock steps back before step 4: the lease is still overdue for this run.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        write_rule_of_bob(&paths);
        let reads = AtomicU64::new(0);
        let clock = || [NOW, 2_000, 1_999][(reads.fetch_add(1, Ordering::SeqCst) as usize).min(2)];
        assert_eq!(reconcile(&paths, &runner, &clock), Ok(()));
        assert_eq!(
            runner.calls(),
            [FIREWALL, &check_timer(2_000), RESTART, &stop_timer(2_000), &check_timer(2_000), START, PROBE, PROBE_POST]
        );
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
        assert_eq!(end_of_record(&paths), 2_000);

        // The revoke fails: no start.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        write_rule_of_bob(&paths);
        let reads = AtomicU64::new(0);
        let clock = || if reads.fetch_add(1, Ordering::SeqCst) == 0 { NOW } else { 2_000 };
        runner.exit(RESTART, 1);
        let error = reconcile(&paths, &runner, &clock).unwrap_err();
        assert!(error.ends_with("; the gateway is stopped"), "{error}");
        assert_eq!(runner.count(START), 0);
        assert_eq!(state(&paths), State::RevokeFailed);

        // Two lease files exist only by hand. The revoke of amy fails (its timer stays active), and bob
        // is still revoked before the run ends.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "amy", 2_000, State::Active);
        seed(&paths, "bob", 2_000, State::Active);
        write_rule_of_bob(&paths);
        runner.exit("systemctl is-active --quiet sparkpass-end-amy-2000.timer", 0);
        let reads = AtomicU64::new(0);
        let clock = || if reads.fetch_add(1, Ordering::SeqCst) == 0 { NOW } else { 2_000 };
        let error = reconcile(&paths, &runner, &clock).unwrap_err();
        // A failed revoke: the gateway stops (owner decision D13).
        assert!(error.ends_with("; the gateway is stopped"), "{error}");
        assert_eq!(runner.count(START), 0);
        assert_eq!(files(&paths.leases), ["amy.json"]);
        assert_eq!(files(&paths.history), ["bob-1000.json"]);
    }

    #[test]
    fn end_time_of_a_revoke_is_the_clock_of_the_revoke() {
        // The firewall command takes 10 seconds: the record ends after it, not at the first read. An overdue
        // lease (step 2), and an active lease whose token file is the deny-all rule (the dead-key gate).
        for (deadline, write_rule) in [(1_000, true), (2_000, false)] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", deadline, State::Active);
            if write_rule {
                write_rule_of_bob(&paths);
            }
            let later = std::sync::Arc::new(AtomicU64::new(NOW));
            runner.hook({
                let later = later.clone();
                move |argv| {
                    if argv.join(" ") == FIREWALL {
                        later.store(NOW + 10, Ordering::SeqCst);
                    }
                }
            });
            assert_eq!(reconcile(&paths, &runner, &|| later.load(Ordering::SeqCst)), Ok(()));
            assert_eq!(end_of_record(&paths), NOW + 10);
        }
    }

    #[test]
    fn firewall_failure_stops_the_gateway() {
        for firewall in [output(1, ""), hang()] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", 1_000, State::Active);
            runner.on(FIREWALL, firewall);
            assert!(reconcile(&paths, &runner, &|| NOW).is_err());
            assert_eq!(runner.calls(), [FIREWALL, STOP]);
            assert_eq!(state(&paths), State::Active);
        }
    }

    #[test]
    fn unreadable_lease_file_stops_the_gateway() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "amy", 1_000, State::Active);
        fs::write(paths.lease("bob"), "not json").unwrap();
        let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
        assert!(error.contains("bob.json"), "{error}");
        assert_eq!(runner.calls(), [FIREWALL, STOP]);
        // Nothing else changed.
        assert_eq!(files(&paths.leases), ["amy.json", "bob.json"]);
    }

    #[test]
    fn failed_lock_stops_the_gateway() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        // The lock creates the state directories first, and a file is in the way.
        fs::remove_dir(&paths.leases).unwrap();
        fs::write(&paths.leases, "").unwrap();
        let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
        assert!(error.contains("cannot take the lock"), "{error}");
        assert_eq!(runner.calls(), [STOP]);
    }

    #[test]
    fn unreadable_lease_directory_stops_the_gateway() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        // The fault starts at the firewall command: after the lock, before the read of the lease directory.
        runner.hook({
            let leases = paths.leases.clone();
            move |argv| {
                if argv[0] == FIREWALL {
                    fs::remove_dir(&leases).unwrap();
                    fs::write(&leases, "").unwrap();
                }
            }
        });
        let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
        assert!(error.contains("cannot read the lease directory"), "{error}");
        assert_eq!(runner.calls(), [FIREWALL, STOP]);
    }

    #[test]
    fn token_with_no_lease_is_removed_before_the_gateway_starts() {
        // For example: the owner removed an unreadable lease file by hand.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        gateway::write_rule(&paths, &gateway::rule(Some(("bob", "abc")))).unwrap();
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        assert_eq!(runner.calls(), [FIREWALL, RESTART, START, PROBE, PROBE_POST]);
        assert!(gateway::is_deny_all(&paths));

        // The deny-all rule cannot be written: the gateway stops and does not start.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::remove_file(&paths.token).unwrap();
        fs::create_dir(&paths.token).unwrap();
        let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
        assert_eq!(runner.calls(), [FIREWALL, STOP, STOP]);
        // Extended by the /ship test coverage audit (2026-10-06): the error names the file to repair.
        // Value: protects=the error of a failed deny-all write in gateway::close names the token file path;
        // fails_when=the format in close drops paths.token.display(), and the owner reads "Is a directory" with no file;
        // why_new=this case and revoke::failed_deny_all_write_stops_the_gateway_with_no_restart asserted the calls only; seam=none
        assert!(error.contains(&paths.token.display().to_string()), "{error}");
    }

    // Added by the /ship test coverage audit (2026-10-06).
    // Value: protects=a failed revoke in the token gate does not start the gateway;
    // fails_when=the error of the gate revoke does not go into `failed`, and `systemctl start caddy` runs after the failed revoke;
    // why_new=the gate tests run with a healthy runner, and the failed-revoke tests reach step 2 only; seam=none
    #[test]
    fn failed_revoke_in_the_token_file_gate_means_no_gateway_start() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        // A power cut in `gateway::write_rule` left an empty token file, and the gateway restart fails.
        fs::write(&paths.token, "").unwrap();
        runner.exit(RESTART, 1);
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        let calls = runner.calls();
        // The stop after the failed restart, and one more at the end: a failed revoke leaves the cut
        // unproven, so no check follows (review of 2026-10-06, owner decision D13).
        assert!(calls.ends_with(&[RESTART.into(), STOP.into(), stop_timer(2_000), check_timer(2_000), STOP.into()]), "{calls:?}");
        assert_eq!(runner.count(START), 0);
        assert_eq!(state(&paths), State::RevokeFailed);
        assert!(gateway::is_deny_all(&paths));

        // The next run with no failure completes the revoke and starts the gateway.
        runner.exit(RESTART, 0);
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        assert_eq!(runner.count(START), 1);
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
        assert_eq!(files(&paths.history), ["bob-1000.json"]);
    }

    #[test]
    fn token_file_that_is_not_the_rule_of_the_active_lease_is_closed_before_the_gateway_starts() {
        let rule_of_bob = gateway::rule(Some(("bob", &"ab".repeat(32))));
        for text in [
            // A power cut in `gateway::write_rule`: after the truncate, or in the middle of the write.
            "",
            &rule_of_bob[..rule_of_bob.len() - 5],
            // The rule of a different lease, and a rule with no token.
            &gateway::rule(Some(("amy", &"ab".repeat(32)))),
            &gateway::rule(Some(("bob", ""))),
            &gateway::rule(Some(("bob", "x\"\nrespond 200\n#"))),
            // A directive after the complete rule can open the gateway.
            &format!("{rule_of_bob}respond 200\n"),
        ] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", 2_000, State::Active);
            fs::write(&paths.token, text).unwrap();
            assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()), "{text:?}");
            // The gate revokes the lease before step 3, because its key is dead: no end timer.
            let calls = runner.calls();
            assert!(calls.ends_with(&[START, PROBE, PROBE_POST].map(String::from)), "{text:?}");
            assert_eq!(runner.count("systemd-run"), 0, "{calls:?}");
            assert_eq!(runner.count(&stop_timer(2_000)), 1, "{calls:?}");
            assert_eq!(runner.count(RESTART), 1, "{calls:?}");
            assert!(gateway::is_deny_all(&paths), "{text:?}");
            assert_eq!(lease::read(&paths, "bob"), Ok(None), "{text:?}");
            assert_eq!(lease::files(&paths.history).len(), 1, "{text:?}");
        }

        // The complete rule of the active lease stays.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        runner.exit(&check_timer(2_000), 0);
        fs::write(&paths.token, &rule_of_bob).unwrap();
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        assert_eq!(runner.calls(), [FIREWALL, &check_timer(2_000), START, PROBE, PROBE_POST, HEALTH]);
        assert_eq!(fs::read_to_string(&paths.token).unwrap(), rule_of_bob);
    }

    #[test]
    fn token_file_gate_runs_also_when_the_timer_check_hangs() {
        // A power cut in `gateway::write_rule` left an empty token file, and the timer check hangs.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        fs::write(&paths.token, "").unwrap();
        runner.on(&check_timer(2_000), hang());
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        // The revoke of the dead key closes the gateway first; its timer stop fails on the hang, so the
        // gateway stops at the end (a failed revoke).
        assert_eq!(runner.calls(), [FIREWALL, RESTART, &stop_timer(2_000), &check_timer(2_000), STOP]);
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(runner.count(START), 0);
        assert_eq!(runner.count("systemd-run"), 0);
        assert_eq!(state(&paths), State::RevokeFailed);
    }

    #[test]
    fn overdue_lease_is_revoked_and_the_gateway_starts_after_it() {
        // The deadline itself is overdue.
        for deadline in [1_000, NOW] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", deadline, State::Active);
            gateway::write_rule(&paths, &gateway::rule(Some(("bob", "abc")))).unwrap();
            assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
            assert_eq!(
                runner.calls(),
                [FIREWALL, RESTART, &stop_timer(deadline), &check_timer(deadline), START, PROBE, PROBE_POST]
            );
            assert!(gateway::is_deny_all(&paths));
            assert_eq!(files(&paths.leases), [] as [&str; 0]);
            assert_eq!(files(&paths.history), ["bob-1000.json"]);
        }
    }

    #[test]
    fn revoke_failed_lease_is_tried_again_before_its_deadline() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::RevokeFailed);
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        assert_eq!(
            runner.calls(),
            [FIREWALL, RESTART, &stop_timer(2_000), &check_timer(2_000), START, PROBE, PROBE_POST]
        );
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
        assert_eq!(files(&paths.history), ["bob-1000.json"]);
    }

    #[test]
    fn active_lease_gets_its_end_timer_when_the_timer_does_not_exist() {
        // The timer counts from the clock before systemd-run: 60 seconds after the first read, or the
        // first read when the clock stepped back by 1000 seconds.
        for (later, on_active) in [(NOW, 500), (NOW + 60, 440), (NOW - 1_000, 500)] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", 2_000, State::Active);
            gateway::write_rule(&paths, &gateway::rule(Some(("bob", "abc")))).unwrap();
            let reads = AtomicU64::new(0);
            let clock = || if reads.fetch_add(1, Ordering::SeqCst) == 0 { NOW } else { later };
            assert_eq!(reconcile(&paths, &runner, &clock), Ok(()));
            let timer = format!(
                "systemd-run --collect --unit=sparkpass-end-bob-2000 --on-calendar=1970-01-01 00:33:20 UTC --on-active={on_active} --timer-property=AccuracySec=1s --timer-property=RemainAfterElapse=no --property=Type=oneshot --property=TimeoutStartSec=240 /usr/local/bin/sparkpass revoke bob --deadline 2000"
            );
            assert_eq!(runner.calls(), [FIREWALL, &check_timer(2_000), &timer, &check_timer(2_000), START, PROBE, PROBE_POST, HEALTH]);
            // The lease and its access stay.
            assert_eq!(state(&paths), State::Active);
            assert!(!gateway::is_deny_all(&paths));
        }
    }

    #[test]
    fn active_lease_gets_no_second_end_timer() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        gateway::write_rule(&paths, &gateway::rule(Some(("bob", &"ab".repeat(32))))).unwrap();
        runner.exit(&check_timer(2_000), 0);
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        assert_eq!(runner.calls(), [FIREWALL, &check_timer(2_000), START, PROBE, PROBE_POST, HEALTH]);
    }

    #[test]
    fn active_lease_with_the_deny_all_rule_is_a_dead_key_and_is_revoked() {
        // A grant that stopped between the lease file and the token write, or a revoke that stopped
        // between its close before the lock and the lock: the guest has no key, and the slot is blocked.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        let calls = runner.calls();
        assert!(calls.ends_with(&[START, PROBE, PROBE_POST].map(String::from)), "{calls:?}");
        assert_eq!(runner.count("systemd-run"), 0, "{calls:?}");
        assert_eq!(runner.count(&stop_timer(2_000)), 1, "{calls:?}");
        assert_eq!(lease::read(&paths, "bob"), Ok(None));
        assert_eq!(lease::files(&paths.history).len(), 1);
        assert!(gateway::is_deny_all(&paths));
    }

    #[test]
    fn failed_revoke_step_means_no_gateway_start_and_a_gateway_stop() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 1_000, State::Active);
        // The end timer is active after the stop.
        runner.exit(&check_timer(1_000), 0);
        // The error is the only report of the failed revoke: revoke itself writes nothing to the journal.
        let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
        assert!(error.contains(REVOKE_FAILED) && error.contains("is active after the stop"), "{error}");
        // A failed revoke leaves the cut unproven: the gateway stops, with no check (owner decision D13).
        assert_eq!(runner.calls(), [FIREWALL, RESTART, &stop_timer(1_000), &check_timer(1_000), STOP]);
        assert_eq!(state(&paths), State::RevokeFailed);

        // The next run with no failure completes the revoke and starts the gateway.
        runner.exit(&check_timer(1_000), 3);
        assert_eq!(reconcile(&paths, &runner, &|| NOW + 300), Ok(()));
        assert_eq!(runner.count(START), 1);
        assert_eq!(runner.count(STOP), 1);
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
    }

    #[test]
    fn failed_timer_create_means_no_gateway_start_and_no_gateway_stop() {
        // systemd-run fails. Or it gives exit code 0 and no timer is active after it: the deadline
        // went into the past after reconcile read the clock.
        for (command, code) in [(create_timer(2_000), 1), (check_timer(2_000), 4)] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", 2_000, State::Active);
            write_rule_of_bob(&paths);
            runner.exit(&command, code);
            assert!(reconcile(&paths, &runner, &|| NOW).is_err());
            assert_eq!(runner.count(&create_timer(2_000)), 1);
            assert_eq!(runner.count(START), 0);
            assert_eq!(runner.count(STOP), 0);
            assert_eq!(state(&paths), State::Active);
        }
    }

    #[test]
    fn command_that_hangs_is_a_failed_step() {
        // Step 3: the timer check hangs.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        write_rule_of_bob(&paths);
        runner.on(&check_timer(2_000), hang());
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        // No start, and the gateway that runs passes its check, so it stays.
        assert_eq!(runner.calls(), [FIREWALL, &check_timer(2_000), CADDY_ACTIVE, PROBE, PROBE_POST]);

        // Step 3: the timer create hangs.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        write_rule_of_bob(&paths);
        runner.on(&create_timer(2_000), hang());
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        assert_eq!(runner.count(START), 0);
        assert_eq!(runner.count(STOP), 0);

        // Step 2: the gateway restart of a revoke hangs. The revoke stops the gateway (D7).
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 1_000, State::Active);
        runner.on(RESTART, hang());
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        // The gateway is stopped, and stopped again at the end (a failed revoke), so no check follows.
        assert_eq!(
            runner.calls(),
            [FIREWALL, RESTART, STOP, &stop_timer(1_000), &check_timer(1_000), STOP]
        );
        assert_eq!(state(&paths), State::RevokeFailed);

        // Step 4: the gateway start hangs.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        runner.on(START, hang());
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        assert_eq!(runner.calls(), [FIREWALL, START, STOP]);
    }

    #[test]
    fn overdue_leases_are_revoked_before_active_leases_get_a_timer() {
        // Two lease files exist only by hand. Here the token file is the rule of amy again after the
        // revoke of bob, so amy keeps its key and gets its timer in step 3.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "amy", 2_000, State::Active);
        seed(&paths, "bob", 1_000, State::Active);
        runner.hook({
            let token = paths.token.clone();
            move |argv| {
                if argv.join(" ") == check_timer(1_000) {
                    fs::write(&token, gateway::rule(Some(("amy", &"ab".repeat(32))))).unwrap();
                }
            }
        });
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        let calls = runner.calls();
        let position = |prefix: &str| calls.iter().position(|call| call.starts_with(prefix)).unwrap();
        assert!(position(RESTART) < position("systemd-run --collect --unit=sparkpass-end-amy-2000"));
        assert_eq!(files(&paths.leases), ["amy.json"]);

        // One token file serves one lease: the revoke of bob wrote the deny-all rule, so the key of
        // amy is dead, and the token gate revokes amy also, before step 3.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "amy", 2_000, State::Active);
        seed(&paths, "bob", 1_000, State::Active);
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        assert_eq!(runner.count("systemd-run"), 0);
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
        assert_eq!(files(&paths.history).len(), 2);

        // The revoke of bob fails (its timer stays active). The gate still runs: amy is revoked, with no timer.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "amy", 2_000, State::Active);
        seed(&paths, "bob", 1_000, State::Active);
        runner.exit(&check_timer(1_000), 0);
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        assert_eq!(runner.count("systemd-run"), 0);
        assert_eq!(files(&paths.leases), ["bob.json"]);
        assert_eq!(state(&paths), State::RevokeFailed);
    }

    #[test]
    fn gateway_marked_open_stays_stopped_also_with_a_lease() {
        for lease in [false, true] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            if lease {
                seed(&paths, "bob", 2_000, State::Active);
                write_rule_of_bob(&paths);
                runner.exit(&check_timer(2_000), 0);
            }
            fs::write(&paths.gateway_open, "the gateway answered 200 through https://spark.example.net/v1/models\n").unwrap();
            let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
            assert!(error.contains("the gateway was proven open earlier") && error.ends_with("the gateway is stopped"), "{error}");
            assert_eq!(runner.count(START), 0);
            assert_eq!(runner.calls().last().map(String::as_str), Some(STOP));
        }
    }

    #[test]
    fn wrong_token_answer_other_than_401_writes_the_marker_and_a_curl_failure_does_not() {
        for (answer, marked) in [(output(0, "200"), true), (output(28, "000"), false)] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            runner.on(PROBE, answer);
            assert!(reconcile(&paths, &runner, &|| NOW).is_err());
            assert_eq!(paths.gateway_open.exists(), marked);
            // The next run: with the marker, no start; without it, the start and the check again.
            let runner = FakeRunner::healthy();
            let _ = reconcile(&paths, &runner, &|| NOW + 300);
            assert_eq!(runner.count(START), usize::from(!marked));
        }
    }

    #[test]
    fn gateway_that_runs_is_checked_also_after_a_failed_step() {
        // A failed step that is not an access cut (the end timer create fails on each run), and a gateway
        // that answers 200.
        let failed_timer = || {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", 2_000, State::Active);
            write_rule_of_bob(&paths);
            runner.exit(&create_timer(2_000), 1);
            (paths, runner)
        };
        let (paths, runner) = failed_timer();
        runner.on(PROBE, output(0, "200"));
        let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
        assert!(error.contains("answered 200") && error.contains("; the gateway is stopped; each reconcile run stops the gateway"), "{error}");
        assert!(runner.calls().ends_with(&[CADDY_ACTIVE, PROBE, STOP].map(String::from)), "{:?}", runner.calls());
        assert!(paths.gateway_open.exists());
        assert_eq!(runner.count(START), 0);

        // A gateway that does not run gets no check and no stop.
        let (paths, runner) = failed_timer();
        runner.exit(CADDY_ACTIVE, 3);
        assert!(reconcile(&paths, &runner, &|| NOW).unwrap_err().ends_with("the gateway was not started"));
        assert_eq!(runner.calls().last().map(String::as_str), Some(CADDY_ACTIVE));
        assert_eq!(runner.count(STOP), 0);
        assert!(!paths.gateway_open.exists());

        // Extended by the /ship test coverage audit (2026-10-06, TODO batch 2): no answer after a failed step.
        // Value: protects=after a failed step, a check of a gateway that runs and gets no answer is no proof, so the gateway stops (with no marker);
        // fails_when=the failed-step branch stops the gateway only on a proven answer, and a gateway with no proof stays up on each run;
        // why_new=this branch had only the case of a 200 answer; seam=none
        let (paths, runner) = failed_timer();
        runner.on(PROBE, hang());
        let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
        assert!(error.contains("failed: curl: no result after 10s") && error.ends_with("the gateway is stopped"), "{error}");
        assert!(runner.calls().ends_with(&[CADDY_ACTIVE, PROBE, STOP].map(String::from)), "{:?}", runner.calls());
        assert!(!paths.gateway_open.exists());
    }

    // Added by the /ship review, Step 11 (2026-10-06, Codex P1, owner decision D13).
    // Value: protects=a failed revoke whose close and stop failed does not leave a running Caddy that a
    // check with a wrong key would accept; the stop runs again; fails_when=the failed-step branch checks a
    // running gateway also after a failed revoke; why_new=each failed-revoke test had a stop that works; seam=none
    #[test]
    fn failed_revoke_with_a_failed_stop_gets_no_check_and_a_new_stop() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 1_000, State::Active);
        write_rule_of_bob(&paths);
        runner.exit(RESTART, 1);
        runner.exit(STOP, 1);
        let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
        assert!(error.ends_with("THE GATEWAY STOP FAILED ALSO: `systemctl stop caddy`: exit code 1: "), "{error}");
        assert_eq!(runner.count(PROBE), 0, "{:?}", runner.calls());
        assert_eq!(runner.count(STOP), 2, "{:?}", runner.calls());
        assert_eq!(runner.calls().last().map(String::as_str), Some(STOP));
        assert_eq!(state(&paths), State::RevokeFailed);
    }

    #[test]
    fn model_outage_during_a_lease_sends_one_notification_and_one_when_it_ends() {
        const NOTIFY: &str = "curl -q -fsS -o /dev/null -m 8 --data-binary ";
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::write(&paths.config, "PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\nGATEWAY_CHECK_ADDRESS=127.0.0.1\nNOTIFY_URL=https://ntfy.example.net/secret-topic\n").unwrap();
        seed(&paths, "bob", 5_000, State::Active);
        write_rule_of_bob(&paths);
        runner.exit(&check_timer(5_000), 0);
        runner.on(HEALTH, output(7, ""));
        // Two runs during the outage: one notification, and the run itself succeeds.
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        assert_eq!(reconcile(&paths, &runner, &|| NOW + 300), Ok(()));
        let sent: Vec<String> = runner.calls().into_iter().filter(|call| call.starts_with(NOTIFY)).collect();
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert!(sent[0].contains("the model endpoint is not healthy") && sent[0].contains("during the lease of bob"), "{sent:?}");
        assert!(paths.model_down.exists());
        // The model answers again: one more notification, and the marker goes.
        runner.on(HEALTH, output(0, r#"{"data":[{"id":"test-model"}]}"#));
        assert_eq!(reconcile(&paths, &runner, &|| NOW + 600), Ok(()));
        let sent: Vec<String> = runner.calls().into_iter().filter(|call| call.starts_with(NOTIFY)).collect();
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert!(sent[1].contains("answers again during the lease of bob"), "{sent:?}");
        assert!(!paths.model_down.exists());

        // With no lease, an old outage marker goes, and no health check runs.
        fs::write(&paths.model_down, "bob\n").unwrap();
        let (paths2, runner) = (paths, FakeRunner::healthy());
        fs::remove_file(paths2.lease("bob")).unwrap();
        gateway::write_rule(&paths2, &gateway::rule(None)).unwrap();
        assert_eq!(reconcile(&paths2, &runner, &|| NOW), Ok(()));
        assert_eq!(runner.count(HEALTH), 0);
        assert!(!paths2.model_down.exists());
    }

    // Added by the /ship review (2026-10-06, TODO batch 2): the stop comes before the notification.
    // Value: protects=a gateway proven open stops at once; the notification (up to one command limit) and
    // its text come after the stop; fails_when=check_gateway notifies before the stop;
    // why_new=no test set NOTIFY_URL on the path of a proven-open gateway; seam=none
    #[test]
    fn proven_open_gateway_stops_before_the_notification() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::write(&paths.config, "PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\nGATEWAY_CHECK_ADDRESS=127.0.0.1\nNOTIFY_URL=https://ntfy.example.net/secret-topic\n").unwrap();
        runner.on(PROBE, output(0, "200"));
        let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
        let calls = runner.calls();
        assert_eq!(calls[calls.len() - 2], STOP, "{calls:?}");
        assert!(calls[calls.len() - 1].starts_with(&format!("curl -q -fsS -o /dev/null -m 8 --data-binary sparkpass: {error} ")), "{calls:?}");
        assert_eq!(runner.count(STOP), 1);
    }

    // Added by the /ship review (2026-10-06, TODO batch 2).
    // Value: protects=an outage during a lease always gives one notification; fails_when=check_model trusts
    // a marker that an earlier lease left; why_new=the outage test has one lease only; seam=none
    #[test]
    fn outage_marker_of_an_earlier_lease_does_not_hide_the_outage_of_the_next_lease() {
        const NOTIFY: &str = "curl -q -fsS -o /dev/null -m 8 --data-binary ";
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::write(&paths.config, "PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\nGATEWAY_CHECK_ADDRESS=127.0.0.1\nNOTIFY_URL=https://ntfy.example.net/secret-topic\n").unwrap();
        // The lease of bob ended during an outage, and amy got a pass before the next reconcile.
        fs::write(&paths.model_down, "bob\n").unwrap();
        seed(&paths, "amy", 5_000, State::Active);
        gateway::write_rule(&paths, &gateway::rule(Some(("amy", &"ab".repeat(32))))).unwrap();
        runner.exit("systemctl is-active --quiet sparkpass-end-amy-5000.timer", 0);
        runner.on(HEALTH, output(7, ""));
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        let sent: Vec<String> = runner.calls().into_iter().filter(|call| call.starts_with(NOTIFY)).collect();
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert!(sent[0].contains("during the lease of amy"), "{sent:?}");
        assert_eq!(fs::read_to_string(&paths.model_down).unwrap(), "amy\n");
    }

    // Added by the /ship review (2026-10-06, TODO batch 2).
    // Value: protects=after a failed step, a gateway in an unknown state stops (fail closed);
    // fails_when=each is-active error counts as "does not run", so the gateway gets no check and no stop;
    // why_new=the failed-step tests have exit codes 0 and 3 only; seam=none
    #[test]
    fn unknown_gateway_state_after_a_failed_step_stops_the_gateway() {
        for answer in [hang(), output(1, "")] {
            // A failed end-timer create: a failed step that is not an access cut.
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", 2_000, State::Active);
            write_rule_of_bob(&paths);
            runner.exit(&create_timer(2_000), 1);
            runner.on(CADDY_ACTIVE, answer);
            let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
            assert!(error.contains("the state of the gateway is unknown") && error.ends_with("; the gateway is stopped"), "{error}");
            assert_eq!(runner.calls().last().map(String::as_str), Some(STOP));
            assert_eq!(runner.count(PROBE), 0);
        }
    }

    // Added by the /ship review (2026-10-06, TODO batch 2, owner decision D3 of the review).
    // Value: protects=the owner learns of a guest with no gateway: one notification for each outage, one at its
    // end, none with no lease; fails_when=reconcile stops the gateway during a lease and sends nothing;
    // why_new=only the model outage and a gateway proven open had notifications; seam=none
    #[test]
    fn gateway_stop_during_a_lease_sends_one_notification_and_one_when_it_runs_again() {
        const NOTIFY: &str = "curl -q -fsS -o /dev/null -m 8 --data-binary ";
        let sent = |runner: &FakeRunner| -> Vec<String> { runner.calls().into_iter().filter(|call| call.starts_with(NOTIFY)).collect() };
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::write(&paths.config, "PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\nGATEWAY_CHECK_ADDRESS=127.0.0.1\nNOTIFY_URL=https://ntfy.example.net/secret-topic\n").unwrap();
        seed(&paths, "bob", 5_000, State::Active);
        write_rule_of_bob(&paths);
        runner.exit(&check_timer(5_000), 0);
        // Two runs with a failed firewall load: the gateway stops on each run, and one notification goes.
        runner.exit(FIREWALL, 1);
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        assert!(reconcile(&paths, &runner, &|| NOW + 300).is_err());
        let messages = sent(&runner);
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(messages[0].contains("the gateway does not run during the lease of bob") && messages[0].contains("the firewall rules did not load"), "{messages:?}");
        // The firewall loads again: the gateway starts with its check, one more notification, and the marker goes.
        runner.exit(FIREWALL, 0);
        assert_eq!(reconcile(&paths, &runner, &|| NOW + 600), Ok(()));
        let messages = sent(&runner);
        assert_eq!(messages.len(), 2, "{messages:?}");
        assert!(messages[1].contains("the gateway runs again during the lease of bob"), "{messages:?}");
        assert!(!paths.gateway_down.exists());

        // A failed step while the gateway runs with its proof: the guest has access, so no notification.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::write(&paths.config, "PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\nGATEWAY_CHECK_ADDRESS=127.0.0.1\nNOTIFY_URL=https://ntfy.example.net/secret-topic\n").unwrap();
        seed(&paths, "bob", 5_000, State::Active);
        write_rule_of_bob(&paths);
        runner.exit(&check_timer(5_000), 3);
        runner.exit(&create_timer(5_000), 1);
        assert!(reconcile(&paths, &runner, &|| NOW).unwrap_err().ends_with("the gateway runs with its proof, and it was not started again"));
        assert_eq!(sent(&runner), [] as [String; 0]);

        // No lease: a stop sends nothing.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::write(&paths.config, "PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\nGATEWAY_CHECK_ADDRESS=127.0.0.1\nNOTIFY_URL=https://ntfy.example.net/secret-topic\n").unwrap();
        runner.exit(FIREWALL, 1);
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        assert_eq!(sent(&runner), [] as [String; 0]);
    }

    const CONFIG_WITH_NOTIFY: &str = "PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\nGATEWAY_CHECK_ADDRESS=127.0.0.1\nNOTIFY_URL=https://ntfy.example.net/secret-topic\n";
    const NOTIFY_CALL: &str = "curl -q -fsS -o /dev/null -m 8 --data-binary ";

    // Added by the /ship review, pass 2 (2026-10-06, TODO batch 2).
    // Value: protects=the guards of gateway_down: one gateway-down message also after the message of
    // mark_open (owner decision D7 of review pass 3), none for a REVOKE-FAILED lease (its revoke sends its
    // own), and one message (and one at the end) for an unreadable lease file;
    // fails_when=one guard goes; why_new=the first gateway-down test has an active lease only; seam=none
    #[test]
    fn gateway_down_sends_one_message_and_counts_an_unreadable_lease() {
        // A gateway proven open during a lease: the message of mark_open, and the gateway-down message (owner
        // decision D7 of review pass 3: a failed send of the first one is not tried again). The next run,
        // stopped by the marker, sends nothing more.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::write(&paths.config, CONFIG_WITH_NOTIFY).unwrap();
        seed(&paths, "bob", 5_000, State::Active);
        write_rule_of_bob(&paths);
        runner.exit(&check_timer(5_000), 0);
        runner.on(PROBE, output(0, "200"));
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        assert!(reconcile(&paths, &runner, &|| NOW + 300).is_err());
        assert_eq!(runner.count(NOTIFY_CALL), 2, "{:?}", runner.calls());
        assert!(runner.calls().iter().any(|call| call.contains("the gateway does not run during the lease of bob")), "{:?}", runner.calls());
        // A REVOKE-FAILED lease sent its own message: the stop sends none.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::write(&paths.config, CONFIG_WITH_NOTIFY).unwrap();
        seed(&paths, "bob", 5_000, State::RevokeFailed);
        runner.exit(FIREWALL, 1);
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        assert_eq!(runner.count(NOTIFY_CALL), 0, "{:?}", runner.calls());
        // An unreadable lease file counts as a lease of its name: one message, and one after the repair.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::write(&paths.config, CONFIG_WITH_NOTIFY).unwrap();
        fs::write(paths.lease("bob"), "not json").unwrap();
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        assert_eq!(runner.count(NOTIFY_CALL), 1, "{:?}", runner.calls());
        assert_eq!(fs::read_to_string(&paths.gateway_down).unwrap(), "bob\n");
        seed(&paths, "bob", 5_000, State::Active);
        write_rule_of_bob(&paths);
        runner.exit(&check_timer(5_000), 0);
        assert_eq!(reconcile(&paths, &runner, &|| NOW + 300), Ok(()));
        let calls = runner.calls();
        assert!(calls.last().unwrap().contains("the gateway runs again during the lease of bob"), "{calls:?}");
    }

    // Added by the /ship review, pass 2 (2026-10-06, TODO batch 2).
    // Value: protects=a gateway-down marker of an earlier lease hides no outage, and a run with no lease
    // removes it with no message; fails_when=gateway_down or gateway_up ignores the lease name;
    // why_new=the model-down marker had this test, the gateway-down marker did not; seam=none
    #[test]
    fn gateway_down_marker_of_an_earlier_lease_does_not_hide_the_next_outage() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::write(&paths.config, CONFIG_WITH_NOTIFY).unwrap();
        fs::write(&paths.gateway_down, "bob\n").unwrap();
        seed(&paths, "amy", 5_000, State::Active);
        runner.exit(FIREWALL, 1);
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        assert_eq!(runner.count(NOTIFY_CALL), 1, "{:?}", runner.calls());
        assert_eq!(fs::read_to_string(&paths.gateway_down).unwrap(), "amy\n");
        // A successful run after the lease ended removes the marker and sends nothing.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::write(&paths.config, CONFIG_WITH_NOTIFY).unwrap();
        fs::write(&paths.gateway_down, "bob\n").unwrap();
        assert_eq!(reconcile(&paths, &runner, &|| NOW), Ok(()));
        assert_eq!(runner.count(NOTIFY_CALL), 0, "{:?}", runner.calls());
        assert!(!paths.gateway_down.exists());
    }

    // Added by the /ship review, pass 2 (2026-10-06, TODO batch 2).
    // Value: protects=a failed send of an outage message is tried again on the next run; fails_when=the
    // marker is written before or whatever the send gives; why_new=each test had a send that works; seam=none
    #[test]
    fn failed_outage_message_is_sent_again_on_the_next_run() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::write(&paths.config, CONFIG_WITH_NOTIFY).unwrap();
        seed(&paths, "bob", 5_000, State::Active);
        write_rule_of_bob(&paths);
        runner.exit(&check_timer(5_000), 0);
        runner.exit(FIREWALL, 1);
        runner.on(NOTIFY_CALL, output(6, ""));
        assert!(reconcile(&paths, &runner, &|| NOW).is_err());
        assert!(reconcile(&paths, &runner, &|| NOW + 300).is_err());
        assert_eq!(runner.count(NOTIFY_CALL), 2, "{:?}", runner.calls());
        assert!(!paths.gateway_down.exists());
        // The same for the model outage.
        runner.exit(FIREWALL, 0);
        runner.on(HEALTH, output(7, ""));
        assert_eq!(reconcile(&paths, &runner, &|| NOW + 600), Ok(()));
        assert!(!paths.model_down.exists());
        // The sends work again: one message, then the marker.
        runner.on(NOTIFY_CALL, output(0, "200"));
        assert_eq!(reconcile(&paths, &runner, &|| NOW + 900), Ok(()));
        assert!(paths.model_down.exists());
        // The end of the outage: a failed send keeps the marker for the next run (added in review pass 3).
        runner.on(HEALTH, output(0, r#"{"data":[{"id":"test-model"}]}"#));
        fs::write(&paths.gateway_down, "bob\n").unwrap();
        runner.exit(NOTIFY_CALL, 6);
        assert_eq!(reconcile(&paths, &runner, &|| NOW + 1_200), Ok(()));
        assert!(paths.model_down.exists() && paths.gateway_down.exists());
        runner.on(NOTIFY_CALL, output(0, "200"));
        assert_eq!(reconcile(&paths, &runner, &|| NOW + 1_500), Ok(()));
        assert!(!paths.model_down.exists() && !paths.gateway_down.exists());
    }

    // Added by the /ship review, pass 3 (2026-10-06, TODO batch 2).
    // Value: protects=a gateway marked open stops also when a step failed and Caddy still runs (no check
    // can pass it); fails_when=the marker gate moves below the failed-step branch; why_new=the marker test
    // had no failed step; seam=none
    #[test]
    fn gateway_marked_open_stops_also_after_a_failed_step_while_it_runs() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        write_rule_of_bob(&paths);
        runner.exit(&create_timer(2_000), 1);
        fs::write(&paths.gateway_open, "the gateway answered 200 through https://spark.example.net/v1/models\n").unwrap();
        let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
        assert!(error.contains("the gateway was proven open earlier") && error.ends_with("the gateway is stopped"), "{error}");
        assert_eq!(runner.count(PROBE), 0, "{:?}", runner.calls());
        assert_eq!(runner.calls().last().map(String::as_str), Some(STOP));
    }

    // Added by the /ship review, pass 3 (2026-10-06, TODO batch 2).
    // Value: protects=the gateway-down message on the failed-step paths where the guest has no access (Caddy
    // does not run; a failed check stops it); fails_when=`runs` is set before the check; why_new=the
    // gateway-down tests reached Err only through fail_closed; seam=none
    #[test]
    fn failed_step_with_a_stopped_gateway_during_a_lease_sends_the_gateway_down_message() {
        for (command, answer) in [(CADDY_ACTIVE, output(3, "")), (PROBE, hang())] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            fs::write(&paths.config, CONFIG_WITH_NOTIFY).unwrap();
            seed(&paths, "bob", 5_000, State::Active);
            write_rule_of_bob(&paths);
            runner.exit(&create_timer(5_000), 1);
            runner.on(command, answer);
            assert!(reconcile(&paths, &runner, &|| NOW).is_err());
            let calls = runner.calls();
            assert!(calls.last().unwrap().starts_with(&format!("{NOTIFY_CALL}sparkpass: the gateway does not run during the lease of bob")), "{calls:?}");
            assert_eq!(fs::read_to_string(&paths.gateway_down).unwrap(), "bob\n");
        }
    }

    // Added by the /ship review, Step 11 round 2 (2026-10-06, Codex P1, owner decision D15).
    // Value: protects=an active lease with no end timer that ends before the next run gets no live key past
    // its end: the gateway stops; a lease that ends later keeps its gateway (with the check); fails_when=a
    // failed timer create never stops the gateway, or always does; why_new=the timer tests had a far deadline; seam=none
    #[test]
    fn active_lease_with_no_end_timer_near_its_end_stops_the_gateway() {
        for (deadline, stops) in [(NOW + 60, true), (NOW + NEXT_RUN, true), (NOW + NEXT_RUN + 1, false)] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", deadline, State::Active);
            write_rule_of_bob(&paths);
            runner.exit(&create_timer(deadline), 1);
            let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
            assert_eq!(runner.count(PROBE), usize::from(!stops), "{deadline}: {:?}", runner.calls());
            assert_eq!(runner.calls().last().map(String::as_str) == Some(STOP), stops, "{deadline}: {error}");
            assert_eq!(state(&paths), State::Active);
        }
    }
}
