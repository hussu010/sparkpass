//! Lease files, the history record, the end timer of a lease, and `sparkpass list`.

use crate::config::{BINARY, Paths};
use crate::runner::{Runner, run_ok};
use crate::time::format_utc;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Active,
    /// A revoke step failed. Access is cut, a new grant is refused, and reconcile tries again.
    RevokeFailed,
}

/// The lease file. It never holds the token.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Lease {
    pub name: String,
    pub start: u64,
    /// Absolute end time. It does not move.
    pub deadline: u64,
    pub state: State,
}

/// The history record: the lease plus its end time.
#[derive(Serialize)]
struct Ended<'a> {
    #[serde(flatten)]
    lease: &'a Lease,
    end: u64,
}

/// `^[a-z][a-z0-9-]{0,30}$`. The name is a part of file names and of a systemd unit name.
pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() <= 31
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// A temporary file in the same directory, then a rename.
fn write_atomic(dir: &Path, file: &str, value: &impl Serialize) -> io::Result<()> {
    let tmp = dir.join(format!("{file}.tmp"));
    let mut out = File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    out.write_all(&serde_json::to_vec(value)?)?;
    out.sync_all()?;
    fs::rename(&tmp, dir.join(file))?;
    // The rename must stay after a power cut: an active token with no lease file has no end.
    File::open(dir)?.sync_all()
}

pub fn write(paths: &Paths, lease: &Lease) -> io::Result<()> {
    write_atomic(&paths.leases, &format!("{}.json", lease.name), lease)
}

/// The second try for the revoke-failed mark. A full disk refuses the temporary file of `write`,
/// and a write in place needs no new block.
/// No truncate at the open: that frees the block before the write. The length is set after the write,
/// because a lease file that the owner repaired by hand can be longer than the new text. A write that
/// stops in the middle leaves an unreadable file, and reconcile stops the gateway for that file (D7).
pub fn overwrite(paths: &Paths, lease: &Lease) -> io::Result<()> {
    let bytes = serde_json::to_vec(lease)?;
    let mut file = File::options().write(true).open(paths.lease(&lease.name))?;
    file.write_all(&bytes)?;
    file.set_len(bytes.len() as u64)?;
    file.sync_all()
}

pub fn write_history(paths: &Paths, lease: &Lease, end: u64) -> io::Result<()> {
    // Two leases with one name can start in the same second: a different deadline gets a suffix. A
    // retried revoke of the same lease (its first try wrote the record, and a later step failed)
    // replaces its own record, with the new end time.
    // ponytail: two leases with the same name, start second, and deadline share one record, for example
    // a script that grants, revokes, and grants again with one TTL in one second.
    let same = |file: &str| {
        fs::read_to_string(paths.history.join(file))
            .ok()
            .and_then(|text| serde_json::from_str::<Lease>(&text).ok())
            .is_some_and(|old| (&old.name, old.start, old.deadline) == (&lease.name, lease.start, lease.deadline))
    };
    let base = format!("{}-{}", lease.name, lease.start);
    let mut file = format!("{base}.json");
    let mut n = 1;
    while paths.history.join(&file).exists() && !same(&file) {
        file = format!("{base}-{n}.json");
        n += 1;
    }
    write_atomic(&paths.history, &file, &Ended { lease, end })
}

/// `Ok(None)`: no lease file. `Err`: the file exists and is unreadable; the caller must fail closed.
pub fn read(paths: &Paths, name: &str) -> Result<Option<Lease>, String> {
    let path = paths.lease(name);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    match serde_json::from_str::<Lease>(&text) {
        // A hand-made file with a bad name would give an end timer that calls `revoke <bad name>`,
        // and the parser refuses that name. Such a file is unreadable, so the caller fails closed.
        Ok(lease) if lease.name == name && valid_name(name) => Ok(Some(lease)),
        Ok(_) => Err(format!("{}: the name field is not the file name, or not a valid name", path.display())),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Each lease file (only files that end in .json), sorted, as (file name, lease or read error).
pub fn read_all(paths: &Paths) -> io::Result<Vec<(String, Result<Lease, String>)>> {
    let mut leases = Vec::new();
    for entry in fs::read_dir(&paths.leases)? {
        let file = entry?.file_name().to_string_lossy().into_owned();
        // transpose: a file that a revoke deleted after read_dir is not a lease.
        if let Some(name) = file.strip_suffix(".json")
            && let Some(lease) = read(paths, name).transpose()
        {
            leases.push((file, lease));
        }
    }
    leases.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(leases)
}

/// `sparkpass list`: one line for each lease. It takes no lock.
pub fn list(paths: &Paths, now: u64) -> Result<String, String> {
    let leases = match read_all(paths) {
        Ok(leases) => leases,
        // No command with the lock ran on this host yet.
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("cannot read {}: {e}", paths.leases.display())),
    };
    if leases.is_empty() {
        return Ok("no lease".into());
    }
    let line = |(file, lease): &(String, Result<Lease, String>)| match lease {
        Ok(lease) => {
            let state = match lease.state {
                State::RevokeFailed => "REVOKE-FAILED",
                State::Active if lease.deadline <= now => "OVERDUE",
                State::Active => "ACTIVE",
            };
            format!("{}  {}  {state}", lease.name, format_utc(lease.deadline))
        }
        Err(_) => format!("UNREADABLE {file}"),
    };
    Ok(leases.iter().map(line).collect::<Vec<_>>().join("\n"))
}

impl Lease {
    /// systemd unit name of the end timer. The deadline makes the name unique for each grant.
    pub fn end_unit(&self) -> String {
        format!("sparkpass-end-{}-{}", self.name, self.deadline)
    }
}

/// A transient systemd timer that runs `sparkpass revoke <name> --deadline <deadline>` at the deadline. Two triggers: the
/// calendar time (it survives a reboot through reconcile) and the monotonic clock (a backward clock
/// step cannot delay it). The earlier one fires.
pub fn create_end_timer(runner: &dyn Runner, lease: &Lease, now: u64) -> Result<(), String> {
    let on_active = format!("--on-active={}", lease.deadline.saturating_sub(now));
    run_ok(
        runner,
        &[
            "systemd-run",
            "--collect",
            &format!("--unit={}", lease.end_unit()),
            &format!("--on-calendar={}", format_utc(lease.deadline)),
            &on_active,
            "--timer-property=AccuracySec=1s",
            // A timer whose time is in the past stays "active (elapsed)" otherwise, and the check below
            // would read it as a live timer.
            "--timer-property=RemainAfterElapse=no",
            "--property=Type=oneshot",
            "--property=TimeoutStartSec=120",
            BINARY,
            "revoke",
            &lease.name,
            // A late run after a new grant of the same name must not revoke the new lease.
            "--deadline",
            &lease.deadline.to_string(),
        ],
    )?;
    // systemd-run can give exit code 0 and leave no active timer (for example a unit that failed at once):
    // the lease then has no end.
    match end_timer_exists(runner, lease)? {
        true => Ok(()),
        false => Err(format!(
            "the end timer {}.timer is not active after systemd-run",
            lease.end_unit()
        )),
    }
}

pub fn end_timer_exists(runner: &dyn Runner, lease: &Lease) -> Result<bool, String> {
    let timer = format!("{}.timer", lease.end_unit());
    match runner.run(&["systemctl", "is-active", "--quiet", &timer]) {
        // No exit code: a signal ended the check. "No timer" is not a safe guess then.
        Ok(out) => out
            .code
            .map(|code| code == 0)
            .ok_or_else(|| format!("cannot check the end timer {timer}: the check gave no exit code")),
        Err(e) => Err(format!("cannot check the end timer {timer}: {e}")),
    }
}

/// Revoke step 3.
pub fn stop_end_timer(runner: &dyn Runner, lease: &Lease) -> Result<(), String> {
    let timer = format!("{}.timer", lease.end_unit());
    // The exit code has no value here: the unit can be gone already. The check below decides.
    let _ = runner.run(&["systemctl", "stop", &timer]);
    match end_timer_exists(runner, lease) {
        Ok(false) => Ok(()),
        Ok(true) => Err(format!("the end timer {timer} is active after the stop")),
        Err(e) => Err(e),
    }
}

/// Test helper: a lease file as grant step 2 writes it.
#[cfg(test)]
pub fn seed(paths: &Paths, name: &str, deadline: u64, state: State) -> Lease {
    let lease = Lease {
        name: name.into(),
        start: 1_000,
        deadline,
        state,
    };
    write(paths, &lease).unwrap();
    lease
}

/// Test helper: the file names in a directory, sorted.
#[cfg(test)]
pub fn files(dir: &Path) -> Vec<String> {
    let mut files: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RunError;
    use crate::runner::fake::FakeRunner;
    use serde_json::{Value, json};
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    #[test]
    fn valid_name_follows_the_pattern() {
        for name in ["a", "bob", "guest-1", "a-", "x9", &"a".repeat(31)] {
            assert!(valid_name(name), "{name:?}");
        }
        for name in [
            "", "Bob", "bOb", "1bob", "-bob", "bob_1", "bob.json", "../bob", "bob/x", "bob smith",
            " bob", "bob\n", "bób", &"a".repeat(32),
        ] {
            assert!(!valid_name(name), "{name:?}");
        }
    }

    #[test]
    fn lease_file_has_the_contract_format_and_mode_0600() {
        let paths = Paths::temp();
        let lease = seed(&paths, "bob", 2_000, State::Active);
        let path = paths.lease("bob");
        let json: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(json, json!({"name": "bob", "start": 1000, "deadline": 2000, "state": "active"}));
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(read(&paths, "bob"), Ok(Some(lease)));
        // The temporary file of the atomic write is gone.
        assert_eq!(files(&paths.leases), ["bob.json"]);

        seed(&paths, "bob", 2_000, State::RevokeFailed);
        let json: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(json["state"], "revoke-failed");
    }

    #[test]
    fn write_fails_when_the_directory_is_missing() {
        let paths = Paths::temp();
        fs::remove_dir(&paths.leases).unwrap();
        let lease = Lease { name: "bob".into(), start: 1, deadline: 2, state: State::Active };
        assert!(write(&paths, &lease).is_err());
    }

    #[test]
    fn write_goes_through_the_temporary_file_and_a_failed_write_keeps_the_old_lease() {
        let paths = Paths::temp();
        let old = seed(&paths, "bob", 2_000, State::Active);
        // The temporary file cannot be created. A write in place does not see this fault.
        fs::create_dir(paths.leases.join("bob.json.tmp")).unwrap();
        assert!(write(&paths, &Lease { state: State::RevokeFailed, ..old.clone() }).is_err());
        assert_eq!(read(&paths, "bob"), Ok(Some(old)));
    }

    #[test]
    fn overwrite_leaves_no_old_text_after_the_new_text() {
        let paths = Paths::temp();
        let marked = Lease { name: "bob".into(), start: 1_000, deadline: 2_000, state: State::RevokeFailed };
        // Files that the owner repaired by hand: `read` accepts white space and unknown fields.
        for text in [
            serde_json::to_string_pretty(&Lease { state: State::Active, ..marked.clone() }).unwrap(),
            r#"{"name":"bob","start":1000,"deadline":2000,"state":"active","note":"repaired by hand"}"#.into(),
        ] {
            fs::write(paths.lease("bob"), text).unwrap();
            assert_eq!(read(&paths, "bob").unwrap().unwrap().state, State::Active);
            overwrite(&paths, &marked).unwrap();
            assert_eq!(read(&paths, "bob"), Ok(Some(marked.clone())));
        }
        // The lease file must exist: this function creates no file.
        assert!(overwrite(&paths, &Lease { name: "amy".into(), ..marked }).is_err());
        assert_eq!(files(&paths.leases), ["bob.json"]);
    }

    #[test]
    fn history_record_is_the_lease_plus_the_end_time() {
        let paths = Paths::temp();
        let lease = seed(&paths, "bob", 2_000, State::Active);
        write_history(&paths, &lease, 1_500).unwrap();
        assert_eq!(files(&paths.history), ["bob-1000.json"]);
        let path = paths.history.join("bob-1000.json");
        let json: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            json,
            json!({"name": "bob", "start": 1000, "deadline": 2000, "state": "active", "end": 1500})
        );
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn history_has_one_record_for_each_lease() {
        let paths = Paths::temp();
        let lease = seed(&paths, "bob", 2_000, State::Active);
        write_history(&paths, &lease, 1_500).unwrap();
        let first = fs::read_to_string(paths.history.join("bob-1000.json")).unwrap();
        // Different leases with the same name and the same start second: each one gets a suffix.
        let second = Lease { deadline: 2_100, ..lease.clone() };
        write_history(&paths, &second, 1_600).unwrap();
        write_history(&paths, &Lease { deadline: 2_200, ..lease.clone() }, 1_700).unwrap();
        assert_eq!(files(&paths.history), ["bob-1000-1.json", "bob-1000-2.json", "bob-1000.json"]);
        assert_eq!(fs::read_to_string(paths.history.join("bob-1000.json")).unwrap(), first);

        // A retried revoke of the second lease replaces its own record: the new end time, no new file.
        let marked = Lease { state: State::RevokeFailed, ..second };
        write_history(&paths, &marked, 1_800).unwrap();
        assert_eq!(files(&paths.history), ["bob-1000-1.json", "bob-1000-2.json", "bob-1000.json"]);
        let record = fs::read_to_string(paths.history.join("bob-1000-1.json")).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&record).unwrap(),
            json!({"name": "bob", "start": 1000, "deadline": 2100, "state": "revoke-failed", "end": 1800})
        );
        assert_eq!(fs::read_to_string(paths.history.join("bob-1000.json")).unwrap(), first);
    }

    #[test]
    fn read_tells_no_lease_from_an_unreadable_lease() {
        let paths = Paths::temp();
        assert_eq!(read(&paths, "bob"), Ok(None));
        for text in [
            "",
            "not json",
            r#"{"name":"bob","start":1,"deadline":2}"#,
            r#"{"name":"bob","start":1,"deadline":2,"state":"paused"}"#,
            r#"{"name":"bob","start":1,"deadline":-2,"state":"active"}"#,
            r#"{"name":"eve","start":1,"deadline":2,"state":"active"}"#,
        ] {
            fs::write(paths.lease("bob"), text).unwrap();
            assert!(read(&paths, "bob").is_err(), "{text:?}");
        }
        // A hand-made file whose name fails the pattern: the end timer would call `revoke Bob`.
        fs::write(paths.lease("Bob"), r#"{"name":"Bob","start":1,"deadline":2,"state":"active"}"#).unwrap();
        assert!(read(&paths, "Bob").is_err());
        assert!(read_all(&paths).unwrap().iter().any(|(file, lease)| file == "Bob.json" && lease.is_err()));
        fs::remove_file(paths.lease("bob")).unwrap();
        fs::create_dir(paths.lease("bob")).unwrap();
        assert!(read(&paths, "bob").is_err());
    }

    #[test]
    fn read_all_reads_only_json_files() {
        let paths = Paths::temp();
        assert_eq!(read_all(&paths).unwrap(), []);
        let bob = seed(&paths, "bob", 2_000, State::Active);
        fs::write(paths.leases.join("eve.json.tmp"), "half a file").unwrap();
        fs::write(paths.leases.join("notes.txt"), "text").unwrap();
        fs::write(paths.lease("amy"), "broken").unwrap();
        let all = read_all(&paths).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0, "amy.json");
        assert!(all[0].1.is_err());
        assert_eq!(all[1], ("bob.json".to_string(), Ok(bob)));
    }

    #[test]
    fn read_all_fails_when_the_lease_directory_is_not_a_directory() {
        let paths = Paths::temp();
        fs::remove_dir(&paths.leases).unwrap();
        fs::write(&paths.leases, "").unwrap();
        assert!(read_all(&paths).is_err());
        assert!(list(&paths, 0).is_err());
    }

    #[test]
    fn list_shows_each_state() {
        let paths = Paths::temp();
        assert_eq!(list(&paths, 1_500), Ok("no lease".into()));

        seed(&paths, "amy", 1_704_067_199, State::Active);
        assert_eq!(list(&paths, 1_704_067_198), Ok("amy  2023-12-31 23:59:59 UTC  ACTIVE".into()));
        // The deadline itself is overdue.
        assert_eq!(list(&paths, 1_704_067_199), Ok("amy  2023-12-31 23:59:59 UTC  OVERDUE".into()));

        seed(&paths, "bob", 4_107_542_400, State::RevokeFailed);
        fs::write(paths.lease("cy"), "{").unwrap();
        fs::create_dir(paths.lease("dan")).unwrap();
        assert_eq!(
            list(&paths, 1_704_067_200).unwrap().lines().collect::<Vec<_>>(),
            [
                "amy  2023-12-31 23:59:59 UTC  OVERDUE",
                "bob  2100-03-01 00:00:00 UTC  REVOKE-FAILED",
                "UNREADABLE cy.json",
                "UNREADABLE dan.json",
            ]
        );
    }

    #[test]
    fn list_works_before_the_state_directory_exists() {
        let paths = Paths::new(&std::env::temp_dir().join("sparkpass-test-no-such-root"));
        assert_eq!(list(&paths, 0), Ok("no lease".into()));
    }

    #[test]
    fn end_timer_is_created_with_the_exact_command() {
        let runner = FakeRunner::default();
        let lease = Lease { name: "bob".into(), start: 1, deadline: 1_709_210_096, state: State::Active };
        assert_eq!(create_end_timer(&runner, &lease, 1_709_210_096 - 300), Ok(()));
        let argv = runner.argv();
        assert_eq!(
            argv[0],
            [
                "systemd-run",
                "--collect",
                "--unit=sparkpass-end-bob-1709210096",
                "--on-calendar=2024-02-29 12:34:56 UTC",
                "--on-active=300",
                "--timer-property=AccuracySec=1s",
                "--timer-property=RemainAfterElapse=no",
                "--property=Type=oneshot",
                "--property=TimeoutStartSec=120",
                "/usr/local/bin/sparkpass",
                "revoke",
                "bob",
                "--deadline",
                "1709210096",
            ]
        );
        assert_eq!(argv[1..], [["systemctl", "is-active", "--quiet", "sparkpass-end-bob-1709210096.timer"]]);
        runner.exit("systemd-run", 1);
        assert!(create_end_timer(&runner, &lease, 1).is_err());
        assert_eq!(runner.count("systemctl is-active"), 1);
    }

    #[test]
    fn end_timer_that_is_not_active_after_its_creation_is_an_error() {
        // systemd-run gives exit code 0, and no timer is active after it.
        let lease = Lease { name: "bob".into(), start: 1, deadline: 2_000, state: State::Active };
        let runner = FakeRunner::default();
        runner.exit("systemctl is-active", 4);
        let error = create_end_timer(&runner, &lease, 1).unwrap_err();
        assert!(error.contains("is not active"), "{error}");
        assert_eq!(runner.count("systemd-run"), 1);

        // The check after the create gives no result: a hung or killed check is not "the timer exists".
        for check in [
            Err(RunError::Timeout(Duration::from_secs(10))),
            Ok(crate::runner::Output { code: None, stdout: String::new(), stderr: String::new() }),
        ] {
            let runner = FakeRunner::default();
            runner.on("systemctl is-active", check);
            assert!(create_end_timer(&runner, &lease, 1).is_err());
            assert_eq!(runner.count("systemd-run"), 1);
        }
    }

    #[test]
    fn end_timer_stop_is_decided_by_the_check_after_the_stop() {
        let lease = Lease { name: "bob".into(), start: 1, deadline: 2_000, state: State::Active };
        const STOP: &str = "systemctl stop sparkpass-end-bob-2000.timer";
        const CHECK: &str = "systemctl is-active --quiet sparkpass-end-bob-2000.timer";

        // The stop command fails because the unit is gone: the step is ok.
        // Each non-zero exit code of the check is "no timer": systemctl gives 3 for a unit that is
        // not active and 4 for a unit that is gone.
        for code in [3, 4] {
            let runner = FakeRunner::default();
            runner.exit(STOP, 5);
            runner.exit(CHECK, code);
            assert_eq!(end_timer_exists(&runner, &lease), Ok(false));
            assert_eq!(stop_end_timer(&runner, &lease), Ok(()));
            assert_eq!(runner.calls(), [CHECK, STOP, CHECK]);
        }

        // The timer is active after the stop: the step failed.
        let runner = FakeRunner::default();
        assert!(stop_end_timer(&runner, &lease).is_err());

        // The check gives no result: the step failed.
        let runner = FakeRunner::healthy();
        runner.on(CHECK, Err(RunError::Timeout(Duration::from_secs(10))));
        assert!(stop_end_timer(&runner, &lease).is_err());

        // A signal ended the check (no exit code): the step failed.
        let no_code = crate::runner::Output { code: None, stdout: String::new(), stderr: String::new() };
        runner.on(CHECK, Ok(no_code));
        assert!(end_timer_exists(&runner, &lease).is_err());
        assert!(stop_end_timer(&runner, &lease).is_err());
    }
}
