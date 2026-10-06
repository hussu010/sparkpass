//! `sparkpass reconcile` (at boot and each 5 minutes). Diagram from the design document:
//!
//! ```text
//! flock
//!  1 firewall rules ── fail ──▶ stop workspace, stop Caddy, exit non-zero
//!    unreadable lease file ──▶ stop Caddy and workspace, exit non-zero (D7)
//!  2 lease overdue or REVOKE-FAILED ──▶ revoke
//!  3 lease active ──▶ attach image, create end timer, start workspace
//!    token file not deny-all and no lease ──▶ close the gateway
//!    token file not the rule of the active lease ──▶ revoke that lease (its key is dead)
//!  4 no failure ──▶ start Caddy
//!    failure in 2 or 3 ──▶ do not start Caddy; a Caddy that runs stays
//! ```
//!
//! Build phase 1 has no workspace and no home image. The step order is the safety property:
//! only this command starts the gateway, and only after each overdue lease is revoked.

use crate::config::{self, Paths};
use crate::gateway;
use crate::lease::{self, Lease, State};
use crate::revoke::revoke;
use crate::runner::{Runner, run_ok};

pub fn reconcile(paths: &Paths, runner: &dyn Runner, now: u64) -> Result<(), String> {
    let _lock = match paths.lock() {
        Ok(lock) => lock,
        Err(e) => return fail_closed(runner, format!("cannot take the lock {}: {e}", paths.lock.display())),
    };
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
    let (ended, active): (Vec<&Lease>, Vec<&Lease>) = leases
        .iter()
        .partition(|lease| lease.deadline <= now || lease.state == State::RevokeFailed);
    let mut failed = Vec::new();
    // 2. Revoke each lease that is overdue or in state revoke-failed.
    for lease in ended {
        if let Err(e) = revoke(paths, runner, &lease.name, now, false) {
            failed.push(e);
        }
    }
    // 3. A reboot removes transient timers: create the end timer again if it does not exist.
    for lease in &active {
        let timer = match lease::end_timer_exists(runner, lease) {
            Ok(true) => Ok(()),
            Ok(false) => lease::create_end_timer(runner, lease, now),
            Err(e) => Err(e),
        };
        if let Err(e) = timer {
            failed.push(e);
        }
    }
    // 4. Start the gateway (no effect if it runs). After a failure: no start, and no stop of a gateway
    // that runs, because an overdue lease has the deny-all rule already.
    if !failed.is_empty() {
        return Err(format!("{}; the gateway was not started", failed.join("; ")));
    }
    // With no lease, the token file must be the deny-all rule. A token with no lease has no end: it
    // stays, for example, after the owner removed an unreadable lease file by hand. An empty or cut
    // file has no token check: a power cut in `gateway::write_rule` leaves it.
    if active.is_empty() {
        if !gateway::is_deny_all(paths) {
            eprintln!("sparkpass: reconcile: the token file holds a rule with no lease; closing the gateway");
            gateway::close(paths, runner)?;
        }
    } else if !active.iter().any(|lease| gateway::is_rule_of(paths, &lease.name)) {
        // With an active lease, the file must be its complete rule. No grant runs under this lock, so
        // each other content (deny-all included: a grant or a revoke that stopped half way) is a dead
        // key. The revoke closes the gateway (steps 2 and 3), records the history, and frees the slot.
        for lease in &active {
            eprintln!(
                "sparkpass: reconcile: the token file is not the rule of lease {}; revoking it, because its key is dead",
                lease.name
            );
            revoke(paths, runner, &lease.name, now, false)?;
        }
    }
    run_ok(runner, &["systemctl", "start", "caddy"]).map(drop)
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
    use std::time::Duration;

    const NOW: u64 = 1_500;
    const FIREWALL: &str = config::FIREWALL;
    const START: &str = "systemctl start caddy";
    const STOP: &str = "systemctl stop caddy";
    const RESTART: &str = "systemctl try-restart caddy";

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

    #[test]
    fn no_lease_starts_the_gateway() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        assert_eq!(reconcile(&paths, &runner, NOW), Ok(()));
        assert_eq!(runner.calls(), [FIREWALL, START]);
    }

    #[test]
    fn failed_gateway_start_is_an_error() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        runner.exit(START, 1);
        assert!(reconcile(&paths, &runner, NOW).is_err());
    }

    #[test]
    fn firewall_failure_stops_the_gateway() {
        for firewall in [output(1, ""), hang()] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", 1_000, State::Active);
            runner.on(FIREWALL, firewall);
            assert!(reconcile(&paths, &runner, NOW).is_err());
            assert_eq!(runner.calls(), [FIREWALL, STOP]);
            assert_eq!(state(&paths), State::Active);
        }
    }

    #[test]
    fn unreadable_lease_file_stops_the_gateway() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "amy", 1_000, State::Active);
        fs::write(paths.lease("bob"), "not json").unwrap();
        let error = reconcile(&paths, &runner, NOW).unwrap_err();
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
        let error = reconcile(&paths, &runner, NOW).unwrap_err();
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
        let error = reconcile(&paths, &runner, NOW).unwrap_err();
        assert!(error.contains("cannot read the lease directory"), "{error}");
        assert_eq!(runner.calls(), [FIREWALL, STOP]);
    }

    #[test]
    fn token_with_no_lease_is_removed_before_the_gateway_starts() {
        // For example: the owner removed an unreadable lease file by hand.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        gateway::write_rule(&paths, &gateway::rule(Some(("bob", "abc")))).unwrap();
        assert_eq!(reconcile(&paths, &runner, NOW), Ok(()));
        assert_eq!(runner.calls(), [FIREWALL, RESTART, START]);
        assert!(gateway::is_deny_all(&paths));

        // The deny-all rule cannot be written: the gateway stops and does not start.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        fs::remove_file(&paths.token).unwrap();
        fs::create_dir(&paths.token).unwrap();
        let error = reconcile(&paths, &runner, NOW).unwrap_err();
        assert_eq!(runner.calls(), [FIREWALL, STOP]);
        // Extended by the /ship test coverage audit (2026-10-06): the error names the file to repair.
        // Value: protects=the error of a failed deny-all write in gateway::close names the token file path;
        // fails_when=the format in close drops paths.token.display(), and the owner reads "Is a directory" with no file;
        // why_new=this case and revoke::failed_deny_all_write_stops_the_gateway_with_no_restart asserted the calls only; seam=none
        assert!(error.contains(&paths.token.display().to_string()), "{error}");
    }

    // Added by the /ship test coverage audit (2026-10-06).
    // Value: protects=a failed revoke in the step 4 token gate does not start the gateway;
    // fails_when=the `?` after the gate revoke is dropped, and `systemctl start caddy` runs after the failed revoke;
    // why_new=the gate tests run with a healthy runner, and the failed-revoke tests reach step 2 only; seam=none
    #[test]
    fn failed_revoke_in_the_token_file_gate_means_no_gateway_start() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        // A power cut in `gateway::write_rule` left an empty token file, and the gateway restart fails.
        fs::write(&paths.token, "").unwrap();
        runner.exit(RESTART, 1);
        assert!(reconcile(&paths, &runner, NOW).is_err());
        let calls = runner.calls();
        assert!(calls.ends_with(&[RESTART.into(), STOP.into(), stop_timer(2_000), check_timer(2_000)]), "{calls:?}");
        assert_eq!(runner.count(START), 0);
        assert_eq!(state(&paths), State::RevokeFailed);
        assert!(gateway::is_deny_all(&paths));

        // The next run with no failure completes the revoke and starts the gateway.
        runner.exit(RESTART, 0);
        assert_eq!(reconcile(&paths, &runner, NOW), Ok(()));
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
        ] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", 2_000, State::Active);
            fs::write(&paths.token, text).unwrap();
            assert_eq!(reconcile(&paths, &runner, NOW), Ok(()), "{text:?}");
            // Step 3 creates the end timer; the gate then revokes the lease, because its key is dead.
            let calls = runner.calls();
            assert_eq!(calls.last().map(String::as_str), Some(START), "{text:?}");
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
        assert_eq!(reconcile(&paths, &runner, NOW), Ok(()));
        assert_eq!(runner.calls(), [FIREWALL, &check_timer(2_000), START]);
        assert_eq!(fs::read_to_string(&paths.token).unwrap(), rule_of_bob);
    }

    #[test]
    fn overdue_lease_is_revoked_and_the_gateway_starts_after_it() {
        // The deadline itself is overdue.
        for deadline in [1_000, NOW] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", deadline, State::Active);
            gateway::write_rule(&paths, &gateway::rule(Some(("bob", "abc")))).unwrap();
            assert_eq!(reconcile(&paths, &runner, NOW), Ok(()));
            assert_eq!(
                runner.calls(),
                [FIREWALL, RESTART, &stop_timer(deadline), &check_timer(deadline), START]
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
        assert_eq!(reconcile(&paths, &runner, NOW), Ok(()));
        assert_eq!(
            runner.calls(),
            [FIREWALL, RESTART, &stop_timer(2_000), &check_timer(2_000), START]
        );
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
        assert_eq!(files(&paths.history), ["bob-1000.json"]);
    }

    #[test]
    fn active_lease_gets_its_end_timer_when_the_timer_does_not_exist() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        gateway::write_rule(&paths, &gateway::rule(Some(("bob", "abc")))).unwrap();
        assert_eq!(reconcile(&paths, &runner, NOW), Ok(()));
        assert_eq!(
            runner.calls(),
            [
                FIREWALL,
                &check_timer(2_000),
                "systemd-run --collect --unit=sparkpass-end-bob-2000 --on-calendar=1970-01-01 00:33:20 UTC --on-active=500 --timer-property=AccuracySec=1s --timer-property=RemainAfterElapse=no --property=Type=oneshot --property=TimeoutStartSec=120 /usr/local/bin/sparkpass revoke bob",
                &check_timer(2_000),
                START
            ]
        );
        // The lease and its access stay.
        assert_eq!(state(&paths), State::Active);
        assert!(!gateway::is_deny_all(&paths));
    }

    #[test]
    fn active_lease_gets_no_second_end_timer() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        gateway::write_rule(&paths, &gateway::rule(Some(("bob", &"ab".repeat(32))))).unwrap();
        runner.exit(&check_timer(2_000), 0);
        assert_eq!(reconcile(&paths, &runner, NOW), Ok(()));
        assert_eq!(runner.calls(), [FIREWALL, &check_timer(2_000), START]);
    }

    #[test]
    fn active_lease_with_the_deny_all_rule_is_a_dead_key_and_is_revoked() {
        // A grant that stopped between the lease file and the token write, or a revoke that stopped
        // between its close before the lock and the lock: the guest has no key, and the slot is blocked.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(reconcile(&paths, &runner, NOW), Ok(()));
        let calls = runner.calls();
        assert_eq!(calls.last().map(String::as_str), Some(START), "{calls:?}");
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
        assert!(reconcile(&paths, &runner, NOW).is_err());
        assert_eq!(runner.calls(), [FIREWALL, RESTART, &stop_timer(1_000), &check_timer(1_000)]);
        assert_eq!(state(&paths), State::RevokeFailed);

        // The next run with no failure completes the revoke and starts the gateway.
        runner.exit(&check_timer(1_000), 3);
        assert_eq!(reconcile(&paths, &runner, NOW + 300), Ok(()));
        assert_eq!(runner.count(START), 1);
        assert_eq!(runner.count(STOP), 0);
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
    }

    #[test]
    fn failed_timer_create_means_no_gateway_start_and_no_gateway_stop() {
        // systemd-run fails. Or it gives exit code 0 and no timer is active after it: the deadline
        // went into the past after main read the clock.
        for (command, code) in [(create_timer(2_000), 1), (check_timer(2_000), 4)] {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            seed(&paths, "bob", 2_000, State::Active);
            runner.exit(&command, code);
            assert!(reconcile(&paths, &runner, NOW).is_err());
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
        runner.on(&check_timer(2_000), hang());
        assert!(reconcile(&paths, &runner, NOW).is_err());
        assert_eq!(runner.calls(), [FIREWALL, &check_timer(2_000)]);

        // Step 3: the timer create hangs.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        runner.on(&create_timer(2_000), hang());
        assert!(reconcile(&paths, &runner, NOW).is_err());
        assert_eq!(runner.count(START), 0);
        assert_eq!(runner.count(STOP), 0);

        // Step 2: the gateway restart of a revoke hangs. The revoke stops the gateway (D7).
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 1_000, State::Active);
        runner.on(RESTART, hang());
        assert!(reconcile(&paths, &runner, NOW).is_err());
        assert_eq!(
            runner.calls(),
            [FIREWALL, RESTART, STOP, &stop_timer(1_000), &check_timer(1_000)]
        );
        assert_eq!(state(&paths), State::RevokeFailed);

        // Step 4: the gateway start hangs.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        runner.on(START, hang());
        assert!(reconcile(&paths, &runner, NOW).is_err());
    }

    #[test]
    fn overdue_leases_are_revoked_before_active_leases_get_a_timer() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "amy", 2_000, State::Active);
        seed(&paths, "bob", 1_000, State::Active);
        assert_eq!(reconcile(&paths, &runner, NOW), Ok(()));
        let calls = runner.calls();
        let position = |prefix: &str| calls.iter().position(|call| call.starts_with(prefix)).unwrap();
        assert!(position(RESTART) < position("systemd-run --collect --unit=sparkpass-end-amy-2000"));
        // One token file serves one lease: the revoke of bob wrote the deny-all rule, so the key of
        // amy is dead, and the token gate revokes amy also. Two lease files exist only by hand.
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
        assert_eq!(files(&paths.history).len(), 2);
    }
}
