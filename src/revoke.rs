//! `sparkpass revoke` (callers: the owner, the end timer, reconcile). Diagram from the design document:
//!
//! ```text
//!  [no lock] write deny-all to the token file ── fail ──▶ stop Caddy, mark REVOKE-FAILED (D7)
//!  [no lock] systemctl try-restart caddy          (open streams close after 2 s)
//!  take flock                                      (each command of the holder has the limit of main.rs)
//!    token file is not deny-all? ──▶ repeat the two steps above (D8)
//!    stop the end timer
//!    docker rm -f workspace                        (SSH sessions end)        [build phase 2]
//!    unmount and delete the home image                                       [build phase 2]
//!    each step ok? ── yes ──▶ record to history/, delete the lease file
//!                 └── no ───▶ REVOKE-FAILED, exit non-zero, journal
//! ```
//!
//! `command` is the full diagram. `revoke` is the part under the lock; grant and reconcile call it
//! under their own lock. The step order is the safety property: access is cut first.

use crate::config::Paths;
use crate::gateway;
use crate::lease::{self, Lease, State};
use crate::runner::Runner;
use std::fs;

/// The internal revoke. It runs under the lock of its caller and never takes the lock. It is idempotent.
/// `closed`: the caller closed the gateway (steps 2 and 3), and the token file is still the deny-all rule.
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
    if !closed && let Err(e) = gateway::close(paths, runner) {
        failed.push(e);
    }
    // 3. Stop the end timer.
    if let Err(e) = lease::stop_end_timer(runner, &lease) {
        failed.push(e);
    }
    // 4 and 5 are build phase 2: remove the workspace container, unmount and delete the home image.
    // 6. History record, then delete the lease file.
    if failed.is_empty()
        && let Err(e) = lease::write_history(paths, &lease, now).and_then(|()| fs::remove_file(paths.lease(name)))
    {
        failed.push(format!("history record: {e}"));
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
    eprintln!("sparkpass: revoke {name}: failed steps: {}", failed.join("; "));
    Err(match mark {
        Ok(()) => format!("the revoke of {name} is not complete (state revoke-failed); reconcile tries it again"),
        Err(_) => format!(
            "the revoke of {name} is not complete, and THE MARK FAILED ALSO: the lease file can still say active, and reconcile can start the gateway; repair the state directory and run `sparkpass revoke {name}` again"
        ),
    })
}

/// `sparkpass revoke <name>`. The gateway closes before the lock (eng review D8),
/// so a different command that holds the lock cannot delay the access cut.
pub fn command(paths: &Paths, runner: &dyn Runner, name: &str, now: u64) -> Result<String, String> {
    // a. A wrong name must not cut a different guest. Only a sure "no" is "no lease":
    // after a failed check the lease can exist, so the gateway closes (fail closed).
    if matches!(paths.lease(name).try_exists(), Ok(false)) {
        return Ok(format!("no lease {name}"));
    }
    // b. Before the lock.
    let closed = gateway::close(paths, runner);
    if let Err(e) = &closed {
        eprintln!("sparkpass: revoke {name}: before the lock: {e}");
    }
    // c.
    let _lock = paths.lock().map_err(|e| format!("cannot take the lock {}: {e}", paths.lock.display()))?;
    // d. A grant can write a token between b and c. Then the internal revoke closes the gateway again.
    let closed = closed.is_ok() && gateway::is_deny_all(paths);
    revoke(paths, runner, name, now, closed)?;
    Ok(format!("lease {name} is revoked"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::{files, seed};
    use crate::runner::RunError;
    use crate::runner::fake::FakeRunner;
    use serde_json::{Value, json};
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
        }
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
        let error = command(&paths, &runner, "bob", 1_500).unwrap_err();
        assert!(error.contains("(state revoke-failed)"), "{error}");
        assert_eq!(state(&paths), State::RevokeFailed);
        // Thus reconcile tries the revoke again before the deadline, and does not start the gateway.
        assert!(crate::reconcile::reconcile(&paths, &runner, 1_600).is_err());
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
            let revoker = scope.spawn(|| command(&paths, &runner, "bob", 1_500));
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
        let lock = paths.lock().unwrap();
        thread::scope(|scope| {
            let revoker = scope.spawn(|| command(&paths, &runner, "bob", 1_500));
            wait_for(|| runner.count(RESTART) == 1);
            drop(lock);
            assert_eq!(revoker.join().unwrap(), Ok("lease bob is revoked".into()));
        });
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(runner.calls(), [RESTART, STOP_TIMER, CHECK_TIMER]);
        assert_eq!(files(&paths.history), ["bob-1000.json"]);
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
        assert_eq!(command(&paths, &runner, "bob", 1_500), Ok("lease bob is revoked".into()));
        assert_eq!(runner.calls(), [STOP, RESTART, STOP_TIMER, CHECK_TIMER]);
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(files(&paths.history), ["bob-1000.json"]);
    }

    // also when the token file is the deny-all rule under the lock.
    #[test]
    fn command_repeats_the_close_under_the_lock_when_the_restart_before_the_lock_failed() {
        let (paths, runner) = active();
        runner.exit(RESTART, 1);
        assert!(command(&paths, &runner, "bob", 1_500).is_err());
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
        let error = command(&paths, &runner, "bob", 1_500).unwrap_err();
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
        let error = command(&paths, &runner, "bob", 1_500).unwrap_err();
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
        assert!(command(&paths, &runner, "bob", 1_500).is_err());
        assert_eq!(state(&paths), State::RevokeFailed);
        assert!(gateway::is_deny_all(&paths));
    }

    #[test]
    fn command_with_a_name_that_has_no_lease_does_not_touch_the_gateway() {
        let (paths, runner) = active();
        assert_eq!(command(&paths, &runner, "eve", 1_500), Ok("no lease eve".into()));
        assert_eq!(runner.calls(), [] as [&str; 0]);
        assert_eq!(fs::read_to_string(&paths.token).unwrap(), active_rule());
        assert_eq!(state(&paths), State::Active);
    }
}
