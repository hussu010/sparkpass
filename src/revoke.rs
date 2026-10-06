//! `sparkpass revoke` (callers: the owner, the end timer, reconcile). Diagram from the design document:
//!
//! ```text
//!  [no lock] end timer of an older lease (no lease file and no rule of this name, or a new deadline) ──▶ nothing to do
//!  [no lock] no lease file, but the rule of this name in the token file ──▶ close the gateway, exit
//!            (no lease file and no rule ──▶ "no lease", exit)
//!  [no lock] write deny-all to the token file ── fail ──▶ stop Caddy (D7)
//!            (not when the file is the rule of a different lease: the key of a new grant)
//!  [no lock] systemctl try-restart caddy ── fail ──▶ stop Caddy    (open streams close after 2 s)
//!  take flock                                      (each command of the holder has the limit of main.rs)
//!    end timer of an older lease? ──▶ nothing to do
//!    close before the lock failed, token file is not deny-all, or lease is REVOKE-FAILED?
//!      ──▶ repeat the two steps above (D8)
//!    stop the end timer
//!    docker rm -f workspace                        (SSH sessions end)        [build phase 2]
//!    unmount and delete the home image                                       [build phase 2]
//!    each step ok? ── yes ──▶ record to history/, delete the lease file
//!                 └── no ───▶ mark REVOKE-FAILED, exit non-zero, journal
//! ```
//!
//! `command` is the full diagram. `revoke` is the part under the lock; grant and reconcile call it
//! under their own lock. The step order is the safety property: access is cut first.

use crate::config::Paths;
use crate::gateway;
use crate::lease::{self, Lease, State};
use crate::runner::Runner;
use std::fs;
use std::io::{self, Write};

/// The internal revoke. It runs under the lock of its caller and never takes the lock. It is idempotent.
/// `closed`: the caller closed the gateway (steps 1 and 2), and the token file is still the deny-all rule.
pub fn revoke(paths: &Paths, runner: &dyn Runner, name: &str, now: u64, closed: bool) -> Result<(), String> {
    let lease = match lease::read(paths, name) {
        Ok(None) => return Ok(()),
        Ok(Some(lease)) => lease,
        Err(e) => {
            // No deadline, thus no timer name: only close the gateway.
            let gateway = if closed { Ok(()) } else { gateway::close(paths, runner) };
            let gateway = gateway.err().unwrap_or_else(|| "the gateway is closed".into());
            return Err(format!("unreadable lease file {e}; {gateway}; repair or remove the file by hand"));
        }
    };
    // Revoke continues past a failed step and remembers it.
    let mut failed = Vec::new();
    // 1. Deny-all rule. 2. Gateway restart; gateway stop if one of the two fails. The access cut comes
    // first: the timer stop below can take two commands, and the token must not stay live meanwhile.
    // `closed` proves only the close of the caller: a revoke-failed lease can hold a token that an
    // earlier failed close left live, so its gateway closes again.
    if (!closed || lease.state == State::RevokeFailed) && let Err(e) = gateway::close(paths, runner) {
        failed.push(e);
    }
    // 3. Stop the end timer.
    if let Err(e) = lease::stop_end_timer(runner, &lease) {
        failed.push(e);
    }
    // 4 and 5 are build phase 2: remove the workspace container, unmount and delete the home image.
    // 6. History record, then delete the lease file. A retry after a failed delete replaces the record
    // of the first try (one record for each lease).
    if failed.is_empty() {
        if let Err(e) = lease::write_history(paths, &lease, now) {
            failed.push(format!("history record: {e}"));
        } else if let Err(e) = fs::remove_file(paths.lease(name)).and_then(|()| fs::File::open(&paths.leases)?.sync_all()) {
            failed.push(format!("delete of the lease file: {e}"));
        }
    }
    if failed.is_empty() {
        return Ok(());
    }
    // The mark must stay: reconcile starts the gateway again for a lease that is active and not overdue.
    let marked = Lease { state: State::RevokeFailed, ..lease };
    let mark = lease::write(paths, &marked).or_else(|_| lease::overwrite(paths, &marked));
    if let Err(e) = &mark {
        failed.push(format!("mark revoke-failed: {e}"));
    }
    // Each caller gives this text to the journal.
    let failed = failed.join("; ");
    Err(match mark {
        Ok(()) => format!("the revoke of {name} is not complete (state revoke-failed); reconcile tries it again; failed steps: {failed}"),
        Err(_) => format!(
            "the revoke of {name} is not complete, and THE MARK FAILED ALSO: the lease file can still say active, and reconcile can start the gateway; repair the state directory and run `sparkpass revoke {name}` again; failed steps: {failed}"
        ),
    })
}

/// `sparkpass revoke <name>`, and the call of the end timer: `deadline` is the deadline of the lease that
/// the timer was made for. The gateway closes before the lock (eng review D8),
/// so a different command that holds the lock cannot delay the access cut.
pub fn command(
    paths: &Paths,
    runner: &dyn Runner,
    name: &str,
    deadline: Option<u64>,
    clock: &dyn Fn() -> u64,
) -> Result<String, String> {
    // The end timer of an older lease of this name: the lease file is gone, or a new grant replaced it.
    // An unreadable lease file is not older: the revoke continues and fails closed. A missing lease file
    // with the complete rule of this name is not older either: that key has no end, and step a closes it.
    let older = || {
        deadline.is_some_and(|d| match lease::read(paths, name) {
            Ok(Some(lease)) => lease.deadline != d,
            Ok(None) => !gateway::is_rule_of(paths, name),
            Err(_) => false,
        })
    };
    let nothing = || Ok(format!("the end timer of an older lease of {name}; nothing to do"));
    if older() {
        return nothing();
    }
    // a. A wrong name must not cut a different guest. Only a sure "no" is "no lease":
    // after a failed check the lease can exist, so the gateway closes (fail closed).
    if matches!(paths.lease(name).try_exists(), Ok(false)) {
        // The complete rule of this name with no lease file: a live key whose lease file is lost, thus a key
        // with no end. A grant writes the lease file before the token, so it is not the key of a grant.
        if !gateway::is_rule_of(paths, name) {
            return Ok(format!("no lease {name}"));
        }
        let lost = format!("the lease file of {name} was missing, and the token file held its rule");
        return gateway::close(paths, runner)
            .map(|()| format!("{lost}; the gateway is closed"))
            .map_err(|e| format!("{lost}: {e}"));
    }
    // b. Before the lock. Not when the token file is the complete rule of a different lease: that is the
    // key of a new grant, because this lease was revoked after a. Under the lock, the internal revoke
    // closes the gateway if this lease still exists.
    // ponytail: a revoke and a new grant of the SAME name between a and this close can still cut the
    // new key; the dead-key gate of reconcile revokes that lease within 5 minutes.
    let closed = match gateway::rule_name(paths) {
        Some(other) if other != name => false,
        _ => gateway::close(paths, runner)
            // Not eprintln!: it panics when the journal stream is gone, and the revoke under the lock must run.
            .inspect_err(|e| {
                let _ = writeln!(io::stderr(), "sparkpass: revoke {name}: before the lock: {e}");
            })
            .is_ok(),
    };
    // c.
    let _lock = paths.lock().map_err(|e| format!("cannot take the lock {}: {e}", paths.lock.display()))?;
    // A revoke and a new grant of this name can run between the first check and the lock.
    if older() {
        return nothing();
    }
    // d. A grant can write a token between b and c. Then the internal revoke closes the gateway again.
    let closed = closed && gateway::is_deny_all(paths);
    // The end time comes after the lock wait.
    revoke(paths, runner, name, clock(), closed)?;
    Ok(format!("lease {name} is revoked"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::{files, seed};
    use crate::runner::RunError;
    use crate::runner::fake::FakeRunner;
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    const STOP_TIMER: &str = "systemctl stop sparkpass-end-bob-2000.timer";
    const CHECK_TIMER: &str = "systemctl is-active --quiet sparkpass-end-bob-2000.timer";
    const RESTART: &str = "systemctl try-restart caddy";
    const STOP: &str = "systemctl stop caddy";

    /// An active lease "bob" with an active token.
    fn active() -> (Paths, FakeRunner) {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        gateway::write_rule(&paths, &active_rule()).unwrap();
        (paths, runner)
    }

    fn active_rule() -> String {
        gateway::rule(Some(("bob", &"ab".repeat(32))))
    }

    fn state(paths: &Paths) -> State {
        lease::read(paths, "bob").unwrap().unwrap().state
    }

    fn make_token_file_unwritable(paths: &Paths) {
        fs::remove_file(&paths.token).unwrap();
        fs::create_dir(&paths.token).unwrap();
    }

    #[test]
    fn revoke_runs_the_steps_in_order_writes_history_and_is_idempotent() {
        let (paths, runner) = active();
        // For each command: is the token file the deny-all rule at that moment?
        let seen = Arc::new(Mutex::new(Vec::new()));
        runner.hook({
            let (seen, token) = (seen.clone(), paths.token.clone());
            move |_| seen.lock().unwrap().push(fs::read_to_string(&token).unwrap() == gateway::rule(None))
        });

        assert_eq!(revoke(&paths, &runner, "bob", 1_500, false), Ok(()));
        assert_eq!(runner.calls(), [RESTART, STOP_TIMER, CHECK_TIMER]);
        // The deny-all write is the first step: the rule is in place at each command.
        assert_eq!(*seen.lock().unwrap(), [true, true, true]);
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
        assert_eq!(files(&paths.history), ["bob-1000.json"]);
        let record = fs::read_to_string(paths.history.join("bob-1000.json")).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&record).unwrap(),
            json!({"name": "bob", "start": 1000, "deadline": 2000, "state": "active", "end": 1500})
        );

        // The second call is a no-op with success.
        assert_eq!(revoke(&paths, &runner, "bob", 1_600, false), Ok(()));
        assert_eq!(runner.calls().len(), 3);
        assert_eq!(fs::read_to_string(paths.history.join("bob-1000.json")).unwrap(), record);
    }

    #[test]
    fn failed_timer_stop_gives_revoke_failed_and_the_gateway_still_closes() {
        for check in [Ok(0), Err(RunError::Timeout(Duration::from_secs(10)))] {
            let (paths, runner) = active();
            match check {
                Ok(code) => runner.exit(CHECK_TIMER, code),
                Err(e) => runner.on(CHECK_TIMER, Err(e)),
            }
            assert!(revoke(&paths, &runner, "bob", 1_500, false).is_err());
            assert_eq!(state(&paths), State::RevokeFailed);
            assert_eq!(files(&paths.history), [] as [&str; 0]);
            // Revoke continues past the failed step.
            assert_eq!(runner.calls(), [RESTART, STOP_TIMER, CHECK_TIMER]);
            assert!(gateway::is_deny_all(&paths));

            // After the block is removed, the next revoke completes.
            runner.exit(CHECK_TIMER, 3);
            assert_eq!(revoke(&paths, &runner, "bob", 1_800, false), Ok(()));
            assert_eq!(files(&paths.leases), [] as [&str; 0]);
            assert_eq!(files(&paths.history), ["bob-1000.json"]);
            // The record of the retry: the marked lease, and the end time of the retry.
            let record = fs::read_to_string(paths.history.join("bob-1000.json")).unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&record).unwrap(),
                json!({"name": "bob", "start": 1000, "deadline": 2000, "state": "revoke-failed", "end": 1800})
            );
        }
    }

    #[test]
    fn revoke_failed_lease_closes_the_gateway_also_when_the_caller_closed_it() {
        // An earlier revoke can have failed at its close: its token can be live in a Caddy that runs.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::RevokeFailed);
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(revoke(&paths, &runner, "bob", 1_500, true), Ok(()));
        assert_eq!(runner.calls(), [RESTART, STOP_TIMER, CHECK_TIMER]);

        // An active lease trusts the close of its caller.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        assert_eq!(revoke(&paths, &runner, "bob", 1_500, true), Ok(()));
        assert_eq!(runner.calls(), [STOP_TIMER, CHECK_TIMER]);
    }

    #[test]
    fn retried_revoke_after_a_failed_delete_leaves_one_record_with_the_end_time_of_the_retry() {
        let (paths, runner) = active();
        // The lease file is gone at the delete (the last command is before it), so the delete fails.
        runner.hook({
            let lease = paths.lease("bob");
            move |argv| {
                if argv.join(" ") == CHECK_TIMER {
                    fs::remove_file(&lease).unwrap();
                }
            }
        });
        let error = revoke(&paths, &runner, "bob", 1_500, false).unwrap_err();
        assert!(error.contains("(state revoke-failed)") && error.contains("failed steps: delete of the lease file: "), "{error}");
        assert!(!error.contains("history record"), "{error}");
        assert_eq!(state(&paths), State::RevokeFailed);
        assert_eq!(files(&paths.history), ["bob-1000.json"]);

        runner.hook(|_| {});
        assert_eq!(revoke(&paths, &runner, "bob", 1_800, false), Ok(()));
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
        assert_eq!(files(&paths.history), ["bob-1000.json"]);
        let record = fs::read_to_string(paths.history.join("bob-1000.json")).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&record).unwrap(),
            json!({"name": "bob", "start": 1000, "deadline": 2000, "state": "revoke-failed", "end": 1800})
        );
    }

    #[test]
    fn failed_deny_all_write_stops_the_gateway_with_no_restart() {
        let (paths, runner) = active();
        make_token_file_unwritable(&paths);
        assert!(revoke(&paths, &runner, "bob", 1_500, false).is_err());
        assert_eq!(runner.calls(), [STOP, STOP_TIMER, CHECK_TIMER]);
        assert_eq!(state(&paths), State::RevokeFailed);
        assert_eq!(files(&paths.history), [] as [&str; 0]);
    }

    #[test]
    fn failed_gateway_restart_stops_the_gateway() {
        for restart in [Ok(1), Err(RunError::Timeout(Duration::from_secs(10)))] {
            let (paths, runner) = active();
            match restart {
                Ok(code) => runner.exit(RESTART, code),
                Err(e) => runner.on(RESTART, Err(e)),
            }
            assert!(revoke(&paths, &runner, "bob", 1_500, false).is_err());
            assert_eq!(runner.calls(), [RESTART, STOP, STOP_TIMER, CHECK_TIMER]);
            assert!(gateway::is_deny_all(&paths));
            assert_eq!(state(&paths), State::RevokeFailed);
            assert_eq!(files(&paths.history), [] as [&str; 0]);
        }
    }

    #[test]
    fn failed_history_write_gives_revoke_failed() {
        let (paths, runner) = active();
        fs::remove_dir(&paths.history).unwrap();
        // Step 6 order: only a lease file that was not deleted before the history write can take the mark in place.
        fs::create_dir(paths.leases.join("bob.json.tmp")).unwrap();
        assert!(revoke(&paths, &runner, "bob", 1_500, false).is_err());
        assert_eq!(state(&paths), State::RevokeFailed);
        // Access is cut already.
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(runner.calls(), [RESTART, STOP_TIMER, CHECK_TIMER]);
    }

    #[test]
    fn revoke_failed_mark_is_written_in_place_when_the_atomic_write_fails() {
        let (paths, runner) = active();
        make_token_file_unwritable(&paths);
        fs::create_dir(paths.leases.join("bob.json.tmp")).unwrap();
        let error = command(&paths, &runner, "bob", None, &|| 1_500).unwrap_err();
        assert!(error.contains("(state revoke-failed)"), "{error}");
        assert_eq!(state(&paths), State::RevokeFailed);
        // Thus reconcile tries the revoke again before the deadline, and does not start the gateway.
        assert!(crate::reconcile::reconcile(&paths, &runner, &|| 1_600).is_err());
        assert_eq!(runner.count("systemctl start caddy"), 0);
        assert_eq!(runner.count("systemd-run"), 0);
        assert_eq!(state(&paths), State::RevokeFailed);
    }

    #[test]
    fn mark_that_failed_is_not_reported_as_state_revoke_failed() {
        for timer_stays in [true, false] {
            let (paths, runner) = active();
            if timer_stays {
                runner.exit(CHECK_TIMER, 0);
            }
            // The lease file is a directory from the timer stop on: no delete and no write.
            runner.hook({
                let lease = paths.lease("bob");
                move |argv| {
                    if argv.join(" ") == STOP_TIMER {
                        fs::remove_file(&lease).unwrap();
                        fs::create_dir(&lease).unwrap();
                    }
                }
            });
            let error = revoke(&paths, &runner, "bob", 1_500, false).unwrap_err();
            assert!(error.contains("THE MARK FAILED ALSO"), "{error}");
            assert!(!error.contains("(state revoke-failed)"), "{error}");
            // Access is cut already.
            assert!(gateway::is_deny_all(&paths));
        }
    }

    #[test]
    fn revoke_with_no_lease_does_nothing() {
        let (paths, runner) = active();
        assert_eq!(revoke(&paths, &runner, "eve", 1_500, false), Ok(()));
        assert_eq!(runner.calls(), [] as [&str; 0]);
        assert_eq!(fs::read_to_string(&paths.token).unwrap(), active_rule());
        assert_eq!(state(&paths), State::Active);
    }

    #[test]
    fn revoke_of_an_unreadable_lease_closes_the_gateway_and_asks_for_a_repair() {
        let (paths, runner) = active();
        fs::write(paths.lease("bob"), "not json").unwrap();
        let error = revoke(&paths, &runner, "bob", 1_500, false).unwrap_err();
        assert!(error.contains("by hand"), "{error}");
        assert_eq!(runner.calls(), [RESTART]);
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(fs::read_to_string(paths.lease("bob")).unwrap(), "not json");
    }

    fn wait_for(what: impl Fn() -> bool) {
        let start = Instant::now();
        while !what() {
            assert!(start.elapsed() < Duration::from_secs(10), "no result in 10 s");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn command_closes_the_gateway_before_the_lock_and_again_after_a_token_write() {
        let (paths, runner) = active();
        let lock = paths.lock().unwrap();
        thread::scope(|scope| {
            let revoker = scope.spawn(|| command(&paths, &runner, "bob", None, &|| 1_500));
            wait_for(|| runner.count(RESTART) == 1);
            // Time for a command that does not wait for the lock to do more.
            thread::sleep(Duration::from_millis(200));
            assert!(!revoker.is_finished());
            assert!(gateway::is_deny_all(&paths));
            assert_eq!(runner.calls(), [RESTART]);
            assert_eq!(state(&paths), State::Active);

            // A grant that holds the lock writes its token.
            gateway::write_rule(&paths, &active_rule()).unwrap();
            drop(lock);
            assert_eq!(revoker.join().unwrap(), Ok("lease bob is revoked".into()));
        });
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(runner.calls(), [RESTART, RESTART, STOP_TIMER, CHECK_TIMER]);
        assert_eq!(files(&paths.leases), [] as [&str; 0]);
        assert_eq!(files(&paths.history), ["bob-1000.json"]);
    }

    #[test]
    fn command_closes_the_gateway_one_time_when_no_token_is_written() {
        let (paths, runner) = active();
        let clock = AtomicU64::new(1_500);
        thread::scope(|scope| {
            // In the scope: a failed assert drops the lock, and the test fails and does not hang.
            let lock = paths.lock().unwrap();
            let revoker = scope.spawn(|| command(&paths, &runner, "bob", None, &|| clock.load(Ordering::SeqCst)));
            wait_for(|| runner.count(RESTART) == 1);
            // The wait for the lock takes time: the end time is the time after the wait.
            clock.store(1_620, Ordering::SeqCst);
            drop(lock);
            assert_eq!(revoker.join().unwrap(), Ok("lease bob is revoked".into()));
        });
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(runner.calls(), [RESTART, STOP_TIMER, CHECK_TIMER]);
        assert_eq!(files(&paths.history), ["bob-1000.json"]);
        let record = fs::read_to_string(paths.history.join("bob-1000.json")).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&record).unwrap()["end"], 1_620);
    }

    #[test]
    fn end_timer_revokes_only_the_lease_that_it_was_made_for() {
        // The deadline of the lease.
        let (paths, runner) = active();
        assert_eq!(command(&paths, &runner, "bob", Some(2_000), &|| 2_000), Ok("lease bob is revoked".into()));
        assert_eq!(runner.calls(), [RESTART, STOP_TIMER, CHECK_TIMER]);
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(files(&paths.history), ["bob-1000.json"]);

        // A late timer of an older lease: bob was revoked and granted again (a new deadline). The new key
        // stays, and nothing is touched.
        for older in [1_900, 2_001] {
            let (paths, runner) = active();
            let before = paths.snapshot();
            let text = command(&paths, &runner, "bob", Some(older), &|| 2_000);
            assert_eq!(text, Ok("the end timer of an older lease of bob; nothing to do".into()));
            assert_eq!(runner.calls(), [] as [&str; 0]);
            assert_eq!(paths.snapshot(), before);
        }
        // No lease file, and the token file holds the key of a new grant of a different name.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        let rule_of_amy = gateway::rule(Some(("amy", &"cd".repeat(32))));
        gateway::write_rule(&paths, &rule_of_amy).unwrap();
        let text = command(&paths, &runner, "bob", Some(2_000), &|| 2_000);
        assert_eq!(text, Ok("the end timer of an older lease of bob; nothing to do".into()));
        assert_eq!(runner.calls(), [] as [&str; 0]);
        assert_eq!(fs::read_to_string(&paths.token).unwrap(), rule_of_amy);

        // No lease file, and the token file holds the rule of bob: a lost lease file, thus a key with no
        // end. A grant writes the lease file before its token, so it is not a new grant. The key closes.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        gateway::write_rule(&paths, &active_rule()).unwrap();
        let text = command(&paths, &runner, "bob", Some(2_000), &|| 2_000);
        assert_eq!(text, Ok("the lease file of bob was missing, and the token file held its rule; the gateway is closed".into()));
        assert_eq!(runner.calls(), [RESTART]);
        assert!(gateway::is_deny_all(&paths));

        // An unreadable lease file can be this lease: the gateway closes (fail closed).
        let (paths, runner) = active();
        fs::write(paths.lease("bob"), "not json").unwrap();
        let error = command(&paths, &runner, "bob", Some(2_000), &|| 2_000).unwrap_err();
        assert!(error.contains("by hand"), "{error}");
        assert_eq!(runner.calls(), [RESTART]);
        assert!(gateway::is_deny_all(&paths));
    }

    #[test]
    fn end_timer_reads_the_lease_again_under_the_lock() {
        let (paths, runner) = active();
        thread::scope(|scope| {
            let lock = paths.lock().unwrap();
            let revoker = scope.spawn(|| command(&paths, &runner, "bob", Some(2_000), &|| 2_000));
            wait_for(|| runner.count(RESTART) == 1);
            // The command that holds the lock revokes bob and grants bob again, with a new deadline.
            seed(&paths, "bob", 3_000, State::Active);
            gateway::write_rule(&paths, &active_rule()).unwrap();
            drop(lock);
            assert_eq!(revoker.join().unwrap(), Ok("the end timer of an older lease of bob; nothing to do".into()));
        });
        assert_eq!(runner.calls(), [RESTART]);
        assert_eq!(lease::read(&paths, "bob").unwrap().unwrap().deadline, 3_000);
        assert_eq!(fs::read_to_string(&paths.token).unwrap(), active_rule());
        assert_eq!(files(&paths.history), [] as [&str; 0]);
    }

    #[test]
    fn command_does_not_cut_the_rule_of_a_different_lease_before_the_lock() {
        // The owner revokes bob. Before the close, a different command revoked bob and granted amy.
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        seed(&paths, "bob", 2_000, State::Active);
        let rule_of_amy = gateway::rule(Some(("amy", &"cd".repeat(32))));
        gateway::write_rule(&paths, &rule_of_amy).unwrap();
        thread::scope(|scope| {
            let lock = paths.lock().unwrap();
            let revoker = scope.spawn(|| command(&paths, &runner, "bob", None, &|| 1_500));
            thread::sleep(Duration::from_millis(200));
            assert!(!revoker.is_finished());
            assert_eq!(runner.calls(), [] as [&str; 0]);
            assert_eq!(fs::read_to_string(&paths.token).unwrap(), rule_of_amy);
            fs::remove_file(paths.lease("bob")).unwrap();
            seed(&paths, "amy", 3_000, State::Active);
            drop(lock);
            assert!(revoker.join().unwrap().is_ok());
        });
        assert_eq!(runner.calls(), [] as [&str; 0]);
        assert_eq!(fs::read_to_string(&paths.token).unwrap(), rule_of_amy);
        assert_eq!(files(&paths.leases), ["amy.json"]);
    }

    #[test]
    fn command_repeats_the_close_under_the_lock_when_the_close_before_the_lock_failed() {
        let (paths, runner) = active();
        make_token_file_unwritable(&paths);
        // The fault ends after the first gateway stop.
        runner.hook({
            let token = paths.token.clone();
            move |argv| {
                if argv.join(" ") == STOP && token.is_dir() {
                    // The tool never creates the token file, so the repair leaves an empty file in place.
                    fs::remove_dir(&token).unwrap();
                    fs::write(&token, "").unwrap();
                }
            }
        });
        assert_eq!(command(&paths, &runner, "bob", None, &|| 1_500), Ok("lease bob is revoked".into()));
        assert_eq!(runner.calls(), [STOP, RESTART, STOP_TIMER, CHECK_TIMER]);
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(files(&paths.history), ["bob-1000.json"]);
    }

    #[test]
    fn command_runs_the_revoke_under_the_lock_when_stderr_is_broken() {
        // eprintln! panics when the journal stream is gone, and the revoke under the lock would not run.
        // libtest captures eprintln!, so the test starts itself again with stderr on /dev/full.
        const GUARD: &str = "SPARKPASS_TEST_BROKEN_STDERR_REVOKE";
        if std::env::var_os(GUARD).is_none() {
            let full = fs::File::options().write(true).open("/dev/full").unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "revoke::tests::command_runs_the_revoke_under_the_lock_when_stderr_is_broken", "--nocapture"])
                .env(GUARD, "1")
                .stdout(std::process::Stdio::null())
                .stderr(full)
                .status()
                .unwrap();
            assert!(status.success(), "{status:?}");
            return;
        }
        // The close before the lock fails, and its message goes to the broken stderr.
        let (paths, runner) = active();
        runner.exit(RESTART, 1);
        assert!(command(&paths, &runner, "bob", None, &|| 1_500).is_err());
        assert_eq!(runner.calls(), [RESTART, STOP, RESTART, STOP, STOP_TIMER, CHECK_TIMER]);
        assert_eq!(state(&paths), State::RevokeFailed);
    }

    // The close under the lock repeats also when the token file is the deny-all rule under the lock.
    #[test]
    fn command_repeats_the_close_under_the_lock_when_the_restart_before_the_lock_failed() {
        let (paths, runner) = active();
        runner.exit(RESTART, 1);
        assert!(command(&paths, &runner, "bob", None, &|| 1_500).is_err());
        assert_eq!(runner.calls(), [RESTART, STOP, RESTART, STOP, STOP_TIMER, CHECK_TIMER]);
        assert_eq!(state(&paths), State::RevokeFailed);
    }

    // Step a: the check of the lease file failed, so the lease can exist. The gateway closes.
    #[test]
    fn command_closes_the_gateway_when_the_check_of_the_lease_file_fails() {
        let (paths, runner) = active();
        // A symbolic link to itself: the stat fails, and the cause is not "no such file".
        fs::remove_file(paths.lease("bob")).unwrap();
        std::os::unix::fs::symlink("bob.json", paths.lease("bob")).unwrap();
        let error = command(&paths, &runner, "bob", None, &|| 1_500).unwrap_err();
        assert!(error.contains("by hand"), "{error}");
        assert_eq!(runner.calls(), [RESTART]);
        assert!(gateway::is_deny_all(&paths));
    }

    #[test]
    fn command_that_cannot_take_the_lock_leaves_the_gateway_closed_and_the_lease_active() {
        let (paths, runner) = active();
        // The fault starts after the close before the lock: the lock file path becomes a directory.
        runner.hook({
            let lock = paths.lock.clone();
            move |argv| {
                if argv.join(" ") == RESTART {
                    let _ = fs::remove_file(&lock);
                    fs::create_dir(&lock).unwrap();
                }
            }
        });
        let error = command(&paths, &runner, "bob", None, &|| 1_500).unwrap_err();
        assert!(error.contains("cannot take the lock"), "{error}");
        assert_eq!(runner.calls(), [RESTART]);
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(state(&paths), State::Active);
        assert_eq!(lease::files(&paths.history), [] as [&str; 0]);
    }

    #[test]
    fn command_reports_a_failed_step() {
        let (paths, runner) = active();
        runner.exit(CHECK_TIMER, 0);
        assert!(command(&paths, &runner, "bob", None, &|| 1_500).is_err());
        assert_eq!(state(&paths), State::RevokeFailed);
        assert!(gateway::is_deny_all(&paths));
    }

    #[test]
    fn command_closes_the_rule_of_the_name_when_its_lease_file_is_missing() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        gateway::write_rule(&paths, &active_rule()).unwrap();
        assert_eq!(
            command(&paths, &runner, "bob", None, &|| 1_500),
            Ok("the lease file of bob was missing, and the token file held its rule; the gateway is closed".into())
        );
        assert_eq!(runner.calls(), [RESTART]);
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(files(&paths.history), [] as [&str; 0]);

        // A failed close is a failure, and the gateway stops.
        gateway::write_rule(&paths, &active_rule()).unwrap();
        runner.exit(RESTART, 1);
        let error = command(&paths, &runner, "bob", None, &|| 1_500).unwrap_err();
        assert!(error.starts_with("the lease file of bob was missing, and the token file held its rule: gateway restart: "), "{error}");
        assert_eq!(runner.calls(), [RESTART, RESTART, STOP]);
    }

    #[test]
    fn command_with_a_name_that_has_no_lease_does_not_touch_the_gateway() {
        let (paths, runner) = active();
        assert_eq!(command(&paths, &runner, "eve", None, &|| 1_500), Ok("no lease eve".into()));
        assert_eq!(runner.calls(), [] as [&str; 0]);
        assert_eq!(fs::read_to_string(&paths.token).unwrap(), active_rule());
        assert_eq!(state(&paths), State::Active);
    }
}
