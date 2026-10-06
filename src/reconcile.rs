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
//!    no failure ──▶ start Caddy ── fail ──▶ stop Caddy, exit non-zero
//!    a wrong token (GET and POST) to the public listener at GATEWAY_CHECK_ADDRESS gets no 401 ──▶ stop Caddy, exit non-zero (D5)
//!    any other failure in 2, 3, or 4 ──▶ do not start Caddy; a Caddy that runs stays
//! ```
//!
//! Build phase 1 has no workspace and no home image. The step order is the safety property:
//! only this command starts the gateway, only after each overdue lease is revoked, and only with
//! the proof that the gateway refuses a wrong token.

use crate::config::{self, Paths, Settings};
use crate::gateway;
use crate::grant::wrong_token_answer;
use crate::lease::{self, Lease, State};
use crate::revoke::revoke;
use crate::runner::{Runner, run_ok};
use std::cell::Cell;
use std::io::{self, Write};
use std::net::IpAddr;

pub fn reconcile(paths: &Paths, runner: &dyn Runner, clock: &dyn Fn() -> u64) -> Result<(), String> {
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
    // 2. Revoke each lease that is overdue or in state revoke-failed.
    for lease in ended {
        // The end time of the record is the time of the revoke: an earlier revoke can have taken 30 seconds.
        if let Err(e) = revoke(paths, runner, &lease.name, clock(), false) {
            failed.push(e);
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
            // clock of this run does not go back, so a backward step can make the timer longer only by the
            // time since the first read (about 20 seconds; see "Timing" in the design document). A deadline
            // that passed in the meantime needs no timer: step 4 revokes that lease.
            Ok(false) => match clock() {
                later if lease.deadline <= later => Ok(()),
                later => lease::create_end_timer(runner, lease, later),
            },
            Err(e) => Err(e),
        };
        if let Err(e) = timer {
            failed.push(e);
        }
    }
    // 4. The clock again, right before the start: a deadline can pass during the steps above.
    let now = clock();
    for lease in active.iter().filter(|lease| lease.deadline <= now) {
        if let Err(e) = revoke(paths, runner, &lease.name, now, false) {
            failed.push(e);
        }
    }
    // Start the gateway (no effect if it runs). After a failure: no start, and no stop of a gateway
    // that runs, because an overdue lease has the deny-all rule already.
    if !failed.is_empty() {
        return Err(format!("{}; the gateway was not started", failed.join("; ")));
    }
    // A start that failed or timed out can still complete in systemd, and that gateway has no proof: stop it.
    // ponytail: one check, right after the start. A Caddy that still waits for its first ACME certificate
    // (a first install, or a host that was off past the end of its certificate) fails the TLS check, and
    // each run stops it again. Upgrade: repeat the check for the time of an ACME order. Until then, the
    // owner starts Caddy by hand, waits for the certificate, and runs reconcile.
    run_ok(runner, &["systemctl", "start", "caddy"])
        .and_then(|_| check_gateway(runner, &settings))
        .or_else(|e| fail_closed(runner, e))
}

/// The proof after each start (TODO branch of 2026-10-06; it extends the self-check of eng review D5):
/// the public listener of this host refuses a wrong token. `--connect-to` with an empty host and port
/// sends each connection to GATEWAY_CHECK_ADDRESS on the port of PUBLIC_URL, never through the public
/// route or DNS, and TLS still checks the name of PUBLIC_URL. No part of the URL is parsed here.
fn check_gateway(runner: &dyn Runner, settings: &Settings) -> Result<(), String> {
    let address = match settings.gateway_check_address {
        IpAddr::V6(address) => format!("[{address}]"),
        address => address.to_string(),
    };
    match wrong_token_answer(runner, &["--connect-to", &format!("::{address}:")], &settings.public_url) {
        None => Ok(()),
        Some((url, Ok(code))) => Err(format!(
            "the gateway answered {code} through {url} at {address} to a request with a wrong token, and it must answer 401: the gateway does not enforce the token file; repair the import of the token file in the Caddyfile"
        )),
        Some((url, Err(e))) => Err(format!("the check with a wrong token through {url} at {address} failed: {e}")),
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
            assert!(error.contains(text) && error.ends_with("; the gateway is stopped"), "{error}");
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
        assert!(error.ends_with("; the gateway was not started"), "{error}");
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
        assert!(error.ends_with("; the gateway was not started"), "{error}");
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
        assert_eq!(runner.calls(), [FIREWALL, STOP]);
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
        assert!(calls.ends_with(&[RESTART.into(), STOP.into(), stop_timer(2_000), check_timer(2_000)]), "{calls:?}");
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
        assert_eq!(runner.calls(), [FIREWALL, &check_timer(2_000), START, PROBE, PROBE_POST]);
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
        // The revoke of the dead key closes the gateway first; its timer stop fails on the hang.
        assert_eq!(runner.calls(), [FIREWALL, RESTART, &stop_timer(2_000), &check_timer(2_000)]);
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
                "systemd-run --collect --unit=sparkpass-end-bob-2000 --on-calendar=1970-01-01 00:33:20 UTC --on-active={on_active} --timer-property=AccuracySec=1s --timer-property=RemainAfterElapse=no --property=Type=oneshot --property=TimeoutStartSec=120 /usr/local/bin/sparkpass revoke bob --deadline 2000"
            );
            assert_eq!(runner.calls(), [FIREWALL, &check_timer(2_000), &timer, &check_timer(2_000), START, PROBE, PROBE_POST]);
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
        assert_eq!(runner.calls(), [FIREWALL, &check_timer(2_000), START, PROBE, PROBE_POST]);
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
    fn failed_revoke_step_means_no_gateway_start_and_no_gateway_stop() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 1_000, State::Active);
        // The end timer is active after the stop.
        runner.exit(&check_timer(1_000), 0);
        // The error is the only report of the failed revoke: revoke itself writes nothing to the journal.
        let error = reconcile(&paths, &runner, &|| NOW).unwrap_err();
        assert!(error.contains(REVOKE_FAILED) && error.contains("is active after the stop"), "{error}");
        assert_eq!(runner.calls(), [FIREWALL, RESTART, &stop_timer(1_000), &check_timer(1_000)]);
        assert_eq!(state(&paths), State::RevokeFailed);

        // The next run with no failure completes the revoke and starts the gateway.
        runner.exit(&check_timer(1_000), 3);
        assert_eq!(reconcile(&paths, &runner, &|| NOW + 300), Ok(()));
        assert_eq!(runner.count(START), 1);
        assert_eq!(runner.count(STOP), 0);
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
        assert_eq!(runner.calls(), [FIREWALL, &check_timer(2_000)]);

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
        assert_eq!(
            runner.calls(),
            [FIREWALL, RESTART, STOP, &stop_timer(1_000), &check_timer(1_000)]
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
}
