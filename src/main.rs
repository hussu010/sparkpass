//! sparkpass: time-limited guest access to the model on the two linked DGX Spark units.
//! Build phase 1: API-only pass. Design: docs/designs/guest-pass-mvp.md (the tool is named `pass` there).

#![forbid(unsafe_code)]

mod config;
mod gateway;
mod grant;
mod lease;
mod reconcile;
mod revoke;
mod runner;
mod time;

use config::Paths;
use runner::{RealRunner, Runner};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Time limit of each system command. `grant::CURL_LIMIT` must stay below it.
const COMMAND_LIMIT: Duration = Duration::from_secs(10);

const USAGE: &str = "usage:
  sparkpass grant <name> --ttl <n>s|m|h|d
  sparkpass revoke <name>
  sparkpass list
  sparkpass reconcile";

#[derive(Debug, PartialEq)]
enum Command {
    Grant { name: String, ttl: u64 },
    Revoke { name: String },
    List,
    Reconcile,
}

fn parse(args: &[&str]) -> Result<Command, String> {
    let name = |name: &str| match lease::valid_name(name) {
        true => Ok(name.to_string()),
        false => Err(format!("bad name '{name}': it must match ^[a-z][a-z0-9-]{{0,30}}$")),
    };
    match args {
        ["grant", guest, "--ttl", ttl] => Ok(Command::Grant {
            name: name(guest)?,
            ttl: time::parse_ttl(ttl)?,
        }),
        ["revoke", guest] => Ok(Command::Revoke { name: name(guest)? }),
        ["list"] => Ok(Command::List),
        ["reconcile"] => Ok(Command::Reconcile),
        _ => Err(USAGE.into()),
    }
}

/// Returns the text for stdout, or the exit code (1 = failure, 2 = usage error) and the text for stderr.
fn run(args: &[&str], paths: &Paths, runner: &dyn Runner, now: u64) -> Result<String, (u8, String)> {
    let failure = |e| (1, e);
    match parse(args).map_err(|e| (2, e))? {
        Command::Grant { name, ttl } => {
            let deadline = now.checked_add(ttl).ok_or((2, "the TTL is too large".to_string()))?;
            grant::grant(paths, runner, &name, now, deadline).map_err(failure)
        }
        Command::Revoke { name } => revoke::command(paths, runner, &name, now).map_err(failure),
        Command::List => lease::list(paths, now).map_err(failure),
        Command::Reconcile => reconcile::reconcile(paths, runner, now)
            .map(|()| String::new())
            .map_err(failure),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        eprintln!("sparkpass: the system clock is before 1970");
        return ExitCode::FAILURE;
    };
    let runner = RealRunner {
        limit: COMMAND_LIMIT,
    };
    match run(&args, &Paths::new(Path::new("/")), &runner, now.as_secs()) {
        Ok(text) => {
            if !text.is_empty() {
                println!("{text}");
            }
            ExitCode::SUCCESS
        }
        Err((code, text)) => {
            eprintln!("sparkpass: {text}");
            ExitCode::from(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::State;
    use crate::runner::fake::FakeRunner;

    #[test]
    fn parse_reads_each_subcommand() {
        assert_eq!(
            parse(&["grant", "bob", "--ttl", "5m"]),
            Ok(Command::Grant { name: "bob".into(), ttl: 300 })
        );
        assert_eq!(
            parse(&["grant", "guest-1", "--ttl", "24h"]),
            Ok(Command::Grant { name: "guest-1".into(), ttl: 86_400 })
        );
        assert_eq!(parse(&["revoke", "bob"]), Ok(Command::Revoke { name: "bob".into() }));
        assert_eq!(parse(&["list"]), Ok(Command::List));
        assert_eq!(parse(&["reconcile"]), Ok(Command::Reconcile));
    }

    #[test]
    fn parse_refuses_bad_input() {
        let bad: [&[&str]; 18] = [
            &[],
            &["help"],
            &["--help"],
            &["grant"],
            &["grant", "bob"],
            &["grant", "bob", "--ttl"],
            &["grant", "bob", "5m"],
            &["grant", "bob", "--ttl", "5m", "extra"],
            &["grant", "bob", "--ttl=5m"],
            &["grant", "--ttl", "5m", "bob"],
            &["grant", "bob", "--pubkey", "key.pub"],
            &["grant", "Bob", "--ttl", "5m"],
            &["grant", "bob", "--ttl", "5"],
            &["revoke"],
            &["revoke", "bob", "amy"],
            &["revoke", "../bob"],
            &["list", "bob"],
            &["reconcile", "now"],
        ];
        for args in bad {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn grant_with_a_bad_name_or_a_bad_ttl_is_a_usage_error_and_writes_no_state() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        let before = paths.snapshot();
        let long = "a".repeat(32);
        let mut bad: Vec<(&str, &str, u64)> = Vec::new();
        for name in ["", "Bob", "1bob", "-bob", "bob_1", "bob.json", "../bob", "bob smith", "bób", &long] {
            bad.push((name, "5m", 1_000));
        }
        for ttl in ["", "5", "m", "0m", "-5m", "+5m", "5x", "5M", "1.5h", "99999999999999999999d", "18446744073709551615m"] {
            bad.push(("bob", ttl, 1_000));
        }
        // The end time does not fit.
        bad.push(("bob", "1m", u64::MAX - 59));
        for (name, ttl, now) in bad {
            let result = run(&["grant", name, "--ttl", ttl], &paths, &runner, now);
            assert!(matches!(result, Err((2, _))), "{name:?} {ttl:?}: {result:?}");
            assert_eq!(runner.calls(), [] as [&str; 0]);
            assert_eq!(paths.snapshot(), before);
        }
    }

    #[test]
    fn run_gives_exit_code_2_for_a_usage_error_and_1_for_a_failure() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        assert_eq!(run(&[], &paths, &runner, 1_000), Err((2, USAGE.into())));
        assert!(matches!(run(&["revoke", "Bob"], &paths, &runner, 1_000), Err((2, _))));
        // The model is down.
        runner.exit("curl", 7);
        assert!(matches!(run(&["grant", "bob", "--ttl", "5m"], &paths, &runner, 1_000), Err((1, _))));
        assert!(matches!(run(&["reconcile"], &paths, &FakeRunner::default(), 1_000), Ok(text) if text.is_empty()));
        runner.exit(config::FIREWALL, 1);
        assert!(matches!(run(&["reconcile"], &paths, &runner, 1_000), Err((1, _))));
        // A revoke step fails.
        lease::seed(&paths, "bob", 2_000, State::Active);
        runner.exit("systemctl try-restart caddy", 1);
        assert!(matches!(run(&["revoke", "bob"], &paths, &runner, 1_000), Err((1, _))));
    }

    #[test]
    fn revoke_reconcile_and_list_work_with_no_settings_file() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        run(&["grant", "bob", "--ttl", "5m"], &paths, &runner, 1_000).unwrap();
        std::fs::remove_file(&paths.config).unwrap();
        assert_eq!(run(&["list"], &paths, &runner, 1_100), Ok("bob  1970-01-01 00:21:40 UTC  ACTIVE".into()));
        assert_eq!(run(&["reconcile"], &paths, &runner, 1_100), Ok(String::new()));
        assert_eq!(run(&["revoke", "bob"], &paths, &runner, 1_100), Ok("lease bob is revoked".into()));
        // A lease that is overdue at the next start of the host.
        lease::seed(&paths, "amy", 1_200, State::Active);
        assert_eq!(run(&["reconcile"], &paths, &runner, 1_300), Ok(String::new()));
        assert_eq!(run(&["list"], &paths, &runner, 1_300), Ok("no lease".into()));
    }

    #[test]
    fn grant_and_reconcile_wait_for_the_lock() {
        let commands: [&[&str]; 2] = [&["grant", "bob", "--ttl", "5m"], &["reconcile"]];
        for args in commands {
            let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
            let lock = paths.lock().unwrap();
            std::thread::scope(|scope| {
                let command = scope.spawn(|| run(args, &paths, &runner, 1_000));
                std::thread::sleep(Duration::from_millis(200));
                assert!(!command.is_finished());
                assert_eq!(runner.calls(), [] as [&str; 0]);
                drop(lock);
                assert!(command.join().unwrap().is_ok());
            });
        }
    }

    #[test]
    fn grant_reconcile_and_revoke_hold_the_lock_at_each_command() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        // Each command that ran while the lock was free: a second open file gets the lock only then.
        let free = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        runner.hook({
            let (free, lock) = (free.clone(), paths.lock.clone());
            move |argv| {
                if std::fs::File::open(&lock).unwrap().try_lock().is_ok() {
                    free.lock().unwrap().push(argv.join(" "));
                }
            }
        });
        run(&["grant", "bob", "--ttl", "5m"], &paths, &runner, 1_000).unwrap();
        run(&["reconcile"], &paths, &runner, 1_100).unwrap();
        run(&["revoke", "bob"], &paths, &runner, 1_200).unwrap();
        // Only the close of `sparkpass revoke` before the lock (eng review D8) runs with no lock.
        assert_eq!(*free.lock().unwrap(), ["systemctl try-restart caddy"]);
    }

    #[test]
    fn list_does_not_wait_for_the_lock() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        let lock = paths.lock().unwrap();
        std::thread::scope(|scope| {
            let list = scope.spawn(|| run(&["list"], &paths, &runner, 1_000));
            let start = std::time::Instant::now();
            while !list.is_finished() && start.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(10));
            }
            // The release is before the assert: a list that waits for the lock must fail, not hang.
            let finished = list.is_finished();
            drop(lock);
            assert!(finished);
        });
    }

    #[test]
    fn run_goes_from_grant_to_list_to_revoke() {
        let (paths, runner) = (Paths::temp(), FakeRunner::healthy());
        assert_eq!(run(&["list"], &paths, &runner, 1_000), Ok("no lease".into()));

        let pass = run(&["grant", "bob", "--ttl", "5m"], &paths, &runner, 1_000).unwrap();
        assert!(pass.contains("End time: 1970-01-01 00:21:40 UTC"), "{pass}");
        let lease = lease::read(&paths, "bob").unwrap().unwrap();
        assert_eq!((lease.start, lease.deadline, lease.state), (1_000, 1_300, State::Active));
        assert_eq!(run(&["list"], &paths, &runner, 1_299), Ok("bob  1970-01-01 00:21:40 UTC  ACTIVE".into()));
        assert_eq!(run(&["list"], &paths, &runner, 1_300), Ok("bob  1970-01-01 00:21:40 UTC  OVERDUE".into()));

        // A second grant is refused while the lease exists.
        assert!(matches!(run(&["grant", "amy", "--ttl", "5m"], &paths, &runner, 1_100), Err((1, _))));

        assert_eq!(run(&["revoke", "amy"], &paths, &runner, 1_200), Ok("no lease amy".into()));
        assert_eq!(run(&["revoke", "bob"], &paths, &runner, 1_200), Ok("lease bob is revoked".into()));
        assert!(gateway::is_deny_all(&paths));
        assert_eq!(run(&["list"], &paths, &runner, 1_200), Ok("no lease".into()));
        assert_eq!(run(&["revoke", "bob"], &paths, &runner, 1_200), Ok("no lease bob".into()));
    }
}
