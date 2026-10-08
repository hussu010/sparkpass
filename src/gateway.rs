//! The gateway (Caddy): the token file, and the commands that close and stop the gateway.

use crate::config::Paths;
use crate::lease;
use crate::notify;
use crate::runner::{Runner, run_ok};
use std::fs::{self, File};
use std::io::{self, Read, Write};

/// The content of the token file. This function is the only place that knows the format, together with
/// gateway/Caddyfile (its guard), tests/gateway.sh (`lease_rule`), which tests it with a real Caddy, and the
/// deny-all text in install.sh and tests/expiry.sh. A test below checks each copy.
/// `None` is the deny-all rule. `Some((name, token))` only sets the pass marker for a request with the
/// token; the Caddyfile answers 401 to each request without the marker, so an empty or cut file, or a
/// rule in an old format, refuses each request (TODO batch 2 of 2026-10-06).
pub fn rule(active: Option<(&str, &str)>) -> String {
    match active {
        None => "# sparkpass: deny-all\nrespond 401\n".into(),
        Some((name, token)) => format!(
            "# sparkpass: lease {name}\n@sparkpass_pass header Authorization \"Bearer {token}\"\nvars @sparkpass_pass sparkpass_pass yes\n"
        ),
    }
}

/// Writes the token file in place, so that the owner and the group that install.sh sets stay.
/// The tool never creates the file: a file that root creates has no group that Caddy can read,
/// and the cause would show only in the journal of Caddy.
pub fn write_rule(paths: &Paths, rule: &str) -> io::Result<()> {
    // The write is not atomic: a power cut between the truncate and the write leaves an empty or cut file.
    // The Caddyfile refuses each request for such a file (no pass marker), and the boot gate of reconcile
    // also closes it before it starts the gateway.
    write_unsynced(paths, rule)?.sync_all()
}

/// The write of `write_rule` without the sync to disk. The caller syncs the returned file.
fn write_unsynced(paths: &Paths, rule: &str) -> io::Result<File> {
    let mut file = File::options().write(true).truncate(true).open(&paths.token)?;
    file.write_all(rule.as_bytes())?;
    Ok(file)
}

pub fn is_deny_all(paths: &Paths) -> bool {
    fs::read_to_string(&paths.token).is_ok_and(|text| text == rule(None))
}

/// The token file is the complete active rule of this lease, with any token.
/// False for the empty or cut file that a power cut in `write_rule` leaves.
pub fn is_rule_of(paths: &Paths, name: &str) -> bool {
    rule_name(paths).is_some_and(|owner| owner == name)
}

/// The lease name of the token file, if the file is the complete active rule of a lease, with any token.
pub fn rule_name(paths: &Paths) -> Option<String> {
    let text = fs::read_to_string(&paths.token).ok()?;
    // `rule` stays the only owner of the format: the name and the token are the texts between its fixed parts.
    let frame = rule(Some(("\0", "\0")));
    let mut parts = frame.split('\0');
    let (head, middle, tail) = (parts.next()?, parts.next()?, parts.next()?);
    let (name, token) = text.strip_prefix(head)?.strip_suffix(tail)?.split_once(middle)?;
    // A name that grant cannot make (a directive in it) is no lease.
    (!token.is_empty() && token.bytes().all(|b| b.is_ascii_hexdigit()) && lease::valid_name(name)).then(|| name.to_string())
}

/// Test helper: the token in a token file that holds an active rule, of any lease.
/// It lives here so that the tests of other modules do not know the format.
#[cfg(test)]
pub fn token_in(token_file: &std::path::Path) -> Option<String> {
    let text = fs::read_to_string(token_file).ok()?;
    let token = text.split("Bearer ").nth(1)?.split('"').next()?;
    Some(token.to_string())
}

/// Test helper: the value of each `KEY=VALUE` line of a systemd unit file for `key`, in order, as systemd reads
/// them: spaces around "=" are allowed, and a comment line ("#" or ";" first) has no key. An empty value is an
/// empty entry; for a list setting such as RuntimeDirectory=, it resets the list (not for a dependency).
#[cfg(test)]
pub fn unit_values<'a>(unit: &'a str, key: &str) -> Vec<&'a str> {
    unit.lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(name, _)| name.trim() == key)
        .map(|(_, value)| value.trim())
        .collect()
}

/// 32 random bytes as 64 lower-case hex characters.
pub fn new_token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Closes the gateway: revoke steps 1 and 2. Safe at any time, with or without the lock.
/// Fail closed (eng review D7): if the gateway cannot close in the normal way, it stops.
pub fn close(paths: &Paths, runner: &dyn Runner) -> Result<(), String> {
    // 1. Deny-all rule. If the write failed, a restart can load the old token: stop, do not restart.
    let file = match write_unsynced(paths, &rule(None)) {
        Ok(file) => file,
        Err(e) => return Err(format!("deny-all write to {}: {e}; {}", paths.token.display(), stop(runner))),
    };
    // 2. The restart closes each open connection after the grace period. No effect if Caddy is not active.
    // It comes before the sync (owner decision of 2026-10-06): a slow or stuck disk must not delay the cut.
    if let Err(e) = run_ok(runner, &["systemctl", "try-restart", "caddy"]) {
        return Err(format!("gateway restart: {e}; {}", stop(runner)));
    }
    // The sync after the cut. Caddy read the rule from memory already. A failed sync is an error, so that
    // the lease stays (REVOKE-FAILED) and reconcile closes again: after a power cut the old rule can return.
    // ponytail: no test fakes a failed or slow sync; a test seam for File::sync_all is not worth it.
    file.sync_all()
        .map_err(|e| format!("the deny-all rule is active, but its sync to disk failed: {e}"))
}

/// The marker of a gateway proven open, as text for an error, or `None` with no marker. A failed check
/// counts as a marker (fail closed).
pub fn open_marker(paths: &Paths) -> Option<String> {
    let marker = paths.gateway_open.display();
    match paths.gateway_open.try_exists() {
        Ok(false) => None,
        Ok(true) => Some(format!(
            "the gateway was proven open earlier ({marker}: {}); it stays stopped until you repair the Caddyfile and remove {marker}",
            fs::read_to_string(&paths.gateway_open).unwrap_or_default().trim()
        )),
        Err(e) => Some(format!("cannot check the marker {marker}: {e}")),
    }
}

/// A proven answer other than 401 to a wrong token: the gateway does not enforce the token file. The gateway
/// stops first: the cut must not wait for the notification. Then the marker keeps it stopped (reconcile
/// does not start it, grant refuses) until the owner repairs the Caddyfile and removes it; a curl failure
/// never writes it. Returns the text for the error, which is also the text of the notification.
pub fn mark_open(paths: &Paths, runner: &dyn Runner, evidence: &str) -> String {
    let stopped = stop(runner);
    let marker = paths.gateway_open.display();
    // The marker must stay after a power cut: the boot run of reconcile reads it. The sync of the file and
    // of its directory, as for a lease file.
    // ponytail: no test fakes a failed sync, as for `close`.
    let write = || -> io::Result<()> {
        let mut file = File::create(&paths.gateway_open)?;
        file.write_all(format!("{evidence}\n").as_bytes())?;
        file.sync_all()?;
        File::open(paths.gateway_open.parent().unwrap_or(std::path::Path::new("/")))?.sync_all()
    };
    let marked = match write() {
        // Each reconcile run stops the gateway while the marker exists, also after a failed stop here.
        Ok(()) => format!("each reconcile run stops the gateway until you repair the Caddyfile and remove {marker}"),
        // A path that exists, or that cannot be checked, counts as a marker (open_marker).
        Err(e) if !matches!(paths.gateway_open.try_exists(), Ok(false)) => {
            format!("THE MARKER {marker} MAY NOT BE COMPLETE ON DISK: {e}; while the path exists or cannot be checked, each reconcile run stops the gateway")
        }
        Err(e) => format!("THE MARKER {marker} WAS NOT WRITTEN: {e}; the next reconcile can start the gateway again"),
    };
    let text = format!("{evidence}; {stopped}; {marked}");
    notify::send(paths, runner, &format!("sparkpass: {text}"));
    text
}

/// Stops the gateway. Returns the result as text for the journal.
pub fn stop(runner: &dyn Runner) -> String {
    match run_ok(runner, &["systemctl", "stop", "caddy"]) {
        Ok(_) => "the gateway is stopped".into(),
        Err(e) => format!("THE GATEWAY STOP FAILED ALSO: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn rule_has_the_exact_format() {
        assert_eq!(rule(None), "# sparkpass: deny-all\nrespond 401\n");
        assert_eq!(
            rule(Some(("bob", "abc123"))),
            "# sparkpass: lease bob\n@sparkpass_pass header Authorization \"Bearer abc123\"\nvars @sparkpass_pass sparkpass_pass yes\n"
        );
    }

    #[test]
    fn token_is_64_lower_case_hex_characters_and_changes() {
        let token = new_token().unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{token}");
        assert_ne!(token, new_token().unwrap());
    }

    // Extended by the /ship test coverage audit (2026-10-06): the "in place" part.
    // Value: protects=write_rule keeps the permissions (thus the owner and the group) of an existing token file;
    // fails_when=the write makes a new file (temporary file and rename, or a create) and does not copy the metadata;
    // why_new=the test checked only the mode of a file that write_rule created; seam=none
    #[test]
    fn write_rule_replaces_the_content_in_place_and_refuses_a_missing_file() {
        let paths = Paths::temp();
        write_rule(&paths, &rule(Some(("bob", &"f".repeat(64))))).unwrap();
        assert!(!is_deny_all(&paths));
        write_rule(&paths, &rule(None)).unwrap();
        assert_eq!(fs::read_to_string(&paths.token).unwrap(), rule(None));
        assert!(is_deny_all(&paths));

        // In place: the permissions of the file stay. A test with no root cannot change the owner
        // or the group, and a new file loses all three.
        fs::set_permissions(&paths.token, fs::Permissions::from_mode(0o600)).unwrap();
        write_rule(&paths, &rule(Some(("bob", &"f".repeat(64))))).unwrap();
        assert_eq!(fs::metadata(&paths.token).unwrap().permissions().mode() & 0o777, 0o600);

        // The tool never creates the file: install.sh owns it, with the group that Caddy can read.
        fs::remove_file(&paths.token).unwrap();
        assert!(!is_deny_all(&paths));
        let err = write_rule(&paths, &rule(None)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(!paths.token.exists());
    }

    #[test]
    fn rule_name_is_the_lease_of_a_complete_rule_only() {
        let paths = Paths::temp();
        let rule_of_bob = rule(Some(("bob", &"ab".repeat(32))));
        for (text, name) in [
            (rule_of_bob.as_str(), Some("bob")),
            (&rule(Some(("guest-1", "f"))), Some("guest-1")),
            (&rule(None), None),
            ("", None),
            (&rule_of_bob[..rule_of_bob.len() - 5], None),
            (&format!("{rule_of_bob}respond 200\n"), None),
            (&rule(Some(("bob", ""))), None),
            (&rule(Some(("bob", "x\"\nrespond 200\n#"))), None),
            (&rule(Some(("bob\nrespond 200", "ab"))), None),
        ] {
            fs::write(&paths.token, text).unwrap();
            assert_eq!(rule_name(&paths).as_deref(), name, "{text:?}");
            assert_eq!(is_rule_of(&paths, "bob"), name == Some("bob"), "{text:?}");
        }
    }

    #[test]
    fn close_writes_deny_all_and_then_restarts() {
        let (paths, runner) = (Paths::temp(), FakeRunner::default());
        write_rule(&paths, &rule(Some(("bob", "abc")))).unwrap();
        assert_eq!(close(&paths, &runner), Ok(()));
        assert!(is_deny_all(&paths));
        assert_eq!(runner.calls(), ["systemctl try-restart caddy"]);
    }

    #[test]
    fn close_reports_a_failed_stop() {
        let (paths, runner) = (Paths::temp(), FakeRunner::default());
        runner.exit("systemctl try-restart caddy", 1);
        runner.exit("systemctl stop caddy", 1);
        let error = close(&paths, &runner).unwrap_err();
        assert!(error.contains("THE GATEWAY STOP FAILED ALSO"), "{error}");
        assert_eq!(runner.calls(), ["systemctl try-restart caddy", "systemctl stop caddy"]);
    }

    #[test]
    fn deny_all_rule_is_in_the_file_when_the_gateway_restarts() {
        let (paths, runner) = (Paths::temp(), FakeRunner::default());
        write_rule(&paths, &rule(Some(("bob", "abc")))).unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        runner.hook({
            let (seen, token) = (seen.clone(), paths.token.clone());
            move |argv| {
                if argv.join(" ") == "systemctl try-restart caddy" {
                    *seen.lock().unwrap() = fs::read_to_string(&token).unwrap();
                }
            }
        });
        assert_eq!(close(&paths, &runner), Ok(()));
        assert_eq!(*seen.lock().unwrap(), rule(None));
    }

    #[test]
    fn marker_of_an_open_gateway_holds_the_evidence_until_the_owner_removes_it() {
        let (paths, runner) = (Paths::temp(), FakeRunner::default());
        fs::write(&paths.config, "NOTIFY_URL=https://ntfy.example.net/secret-topic\n").unwrap();
        assert_eq!(open_marker(&paths), None);
        let text = mark_open(&paths, &runner, "the gateway answered 200 through https://x/v1/models to a request with a wrong token");
        assert!(text.contains("wrong token; the gateway is stopped; each reconcile run stops the gateway until you repair the Caddyfile and remove "), "{text}");
        let marker = open_marker(&paths).unwrap();
        assert!(marker.contains("answered 200 through https://x/v1/models") && marker.contains("remove"), "{marker}");
        // The stop first, then one notification with the same text: the cut does not wait for the notification.
        let calls = runner.calls();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(calls[0], "systemctl stop caddy");
        assert!(calls[1].starts_with(&format!("curl -q -fsS -o /dev/null -m 8 --data-binary sparkpass: {text} ")), "{calls:?}");
        fs::remove_file(&paths.gateway_open).unwrap();
        assert_eq!(open_marker(&paths), None);

        // The marker write fails, but a path exists, which still counts as a marker: the text says so. The
        // notification says what is true: the stop failed too.
        fs::create_dir(&paths.gateway_open).unwrap();
        let runner = FakeRunner::default();
        runner.exit("systemctl stop caddy", 1);
        let text = mark_open(&paths, &runner, "evidence");
        assert!(text.contains("THE GATEWAY STOP FAILED ALSO") && text.contains("MAY NOT BE COMPLETE ON DISK"), "{text}");
        assert!(runner.calls().last().unwrap().contains(&text), "{:?}", runner.calls());
        assert!(open_marker(&paths).is_some());

        // No marker file at all (the state directory is gone): the next reconcile can start the gateway.
        let gone = Paths::temp();
        fs::remove_dir_all(gone.gateway_open.parent().unwrap()).unwrap();
        let text = mark_open(&gone, &FakeRunner::default(), "evidence");
        assert!(text.contains("WAS NOT WRITTEN") && text.contains("the next reconcile can start the gateway again"), "{text}");

        // Extended by the /ship test coverage audit (2026-10-06, TODO batch 2): a failed check of the marker.
        // Value: protects=a marker path that cannot be checked counts as a marker, so grant refuses and reconcile keeps the gateway stopped;
        // fails_when=open_marker uses Path::exists (false on an error), and a gateway proven open starts again when the stat fails;
        // why_new=the cases above (no marker, a file, a directory) give the same result with exists(); seam=none
        fs::remove_dir(&paths.gateway_open).unwrap();
        // A symbolic link to itself: the stat fails, and the cause is not "no such file".
        std::os::unix::fs::symlink("gateway-open", &paths.gateway_open).unwrap();
        let text = open_marker(&paths).unwrap_or_default();
        assert!(text.starts_with("cannot check the marker"), "{text}");
        // The text of mark_open agrees: the gateway stays stopped (added by the /ship review, Step 11 round 3).
        let text = mark_open(&paths, &FakeRunner::default(), "evidence");
        assert!(text.contains("MAY NOT BE COMPLETE ON DISK") && !text.contains("can start the gateway again"), "{text}");
    }

    // Added by the /ship test coverage audit (2026-10-06, TODO batch 2).
    // Value: protects=tests/gateway.sh proves with a real Caddy the exact text that `rule` writes, and the guard of
    // gateway/Caddyfile reads the pass marker that `rule` sets, from the token file of production;
    // fails_when=one of the copies of the format changes alone: gateway.sh then passes for a rule that the tool
    // never writes (an open matcher goes unseen), or each pass gets 401 on the units;
    // why_new=rule_has_the_exact_format pins `rule` alone, and gateway.sh pins only its own copy; seam=none
    #[test]
    fn token_rule_is_the_same_in_the_caddyfile_and_in_the_gateway_test() {
        // deny_all and lease_rule of tests/gateway.sh: `rule` as a printf format, with %s for the name and the token.
        let script = include_str!("../tests/gateway.sh");
        let printf = |text: String| format!("printf '{}'", text.replace('\n', "\\n"));
        for text in [rule(None), rule(Some(("%s", "%s")))] {
            assert!(script.contains(&printf(text.clone())), "tests/gateway.sh has no {}", printf(text));
        }
        // install.sh writes the deny-all rule, and tests/expiry.sh compares the token file with it.
        for (file, script) in [("install.sh", include_str!("../install.sh")), ("tests/expiry.sh", include_str!("../tests/expiry.sh"))] {
            assert!(script.contains(&printf(rule(None))), "{file} has no {}", printf(rule(None)));
        }
        let caddyfile: Vec<&str> = include_str!("../gateway/Caddyfile").lines().map(str::trim).collect();
        let import = format!("import {}", Paths::new(std::path::Path::new("/")).token.display());
        assert!(caddyfile.contains(&import.as_str()), "gateway/Caddyfile has no {import}");
        // The last line of an active rule is `vars <matcher> <name> <value>`. The guard refuses each request
        // that does not have this name with this value.
        let active = rule(Some(("bob", "ab")));
        let vars: Vec<&str> = active.lines().last().unwrap().split(' ').collect();
        assert!(vars.len() == 4 && vars[0] == "vars", "{active}");
        let guard = format!(" not vars {} {}", vars[2], vars[3]);
        assert!(caddyfile.iter().any(|line| line.ends_with(&guard)), "gateway/Caddyfile has no guard{guard}");
    }

    // Added by the /ship test coverage audit (2026-10-07, branch feat/tunnel-and-p1-code).
    // Value: protects=a first install (install.sh copies etc/caddy.env.example) leaves SPARKPASS_BIND unset, so
    // Caddy listens on 127.0.0.1 only; fails_when=the template gets a SPARKPASS_BIND line, also an empty one as for
    // SPARKPASS_SITE: Caddy 2.6.2 (Ubuntu 24.04) then listens on all addresses; why_new=tests/gateway.sh adapts the
    // Caddyfile with the variable unset, and install.sh only warns, on the unit; seam=none
    #[test]
    fn caddy_env_template_sets_no_listen_address() {
        // The keys of the KEY=VALUE lines, as systemd reads the EnvironmentFile: "#" starts a comment line.
        let keys: Vec<&str> = include_str!("../etc/caddy.env.example")
            .lines()
            .map(str::trim_start)
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.split_once('=').map(|(key, _)| key.trim_end()))
            .collect();
        // The parse finds the two values that the owner fills, so the check below is not empty.
        assert!(keys.contains(&"SPARKPASS_SITE") && keys.contains(&"SPARKPASS_MODEL_PORT"), "{keys:?}");
        assert!(!keys.contains(&"SPARKPASS_BIND"), "etc/caddy.env.example sets SPARKPASS_BIND: {keys:?}");
    }

    // Added for the TODO item "Review follow-ups of the Funnel branch", item 1 (2026-10-08).
    // Value: protects=the unit-file tests read a key as systemd does; fails_when=unit_values matches the
    // text "Key=" (a line "Wants = x" is then missed) or reads a comment line; why_new=the test of
    // pass-reconcile.service missed "Wants = tailscaled.service"; seam=none
    #[test]
    fn unit_values_reads_each_line_of_a_key_as_systemd_does() {
        let unit = "[Unit]\nWants = a.service  b.service\n#Wants=c.service\n; Wants=d.service\nWantsX=e.service\nWants=\n";
        assert_eq!(unit_values(unit, "Wants"), ["a.service  b.service", ""]);
    }

    // Added by the /ship test coverage audit, pass 2 (2026-10-07, branch feat/tunnel-and-p1-code).
    // Value: protects=the admin socket of gateway/Caddyfile is in a directory that RuntimeDirectory= of the
    // caddy.service drop-in makes for the caddy user; fails_when=the drop-in loses RuntimeDirectory=caddy, or one
    // file moves the socket alone: on the unit Caddy does not start, and no grant works; why_new=tests/gateway.sh
    // makes /run/caddy itself, and no test reads systemd/caddy-sparkpass.conf; seam=none
    // Extended for the TODO item "Review follow-ups of the Funnel branch", item 1 (2026-10-08): an empty
    // RuntimeDirectory= line resets the list.
    #[test]
    fn admin_socket_is_in_the_runtime_directory_of_the_caddy_unit() {
        use std::path::{Path, PathBuf};
        let socket = include_str!("../gateway/Caddyfile")
            .lines()
            .find_map(|line| line.trim().strip_prefix("admin unix/"))
            .expect("gateway/Caddyfile has no admin socket");
        // systemd makes /run/<name> for each name of RuntimeDirectory= (a list) at each start of caddy.service.
        // An empty value resets the list: only the lines after the last empty one count.
        let runtime_directories = |unit| -> Vec<PathBuf> {
            let lines = unit_values(unit, "RuntimeDirectory");
            let after_reset = lines.rsplit(|value| value.is_empty()).next().unwrap_or_default();
            after_reset.iter().flat_map(|names| names.split_whitespace()).map(|name| Path::new("/run").join(name)).collect()
        };
        assert_eq!(runtime_directories("RuntimeDirectory=caddy\nRuntimeDirectory=\n"), [] as [PathBuf; 0]);
        assert_eq!(runtime_directories("RuntimeDirectory=\nRuntimeDirectory = caddy x\n"), [Path::new("/run/caddy"), Path::new("/run/x")]);
        let made = runtime_directories(include_str!("../systemd/caddy-sparkpass.conf"));
        let directory = Path::new(socket).parent();
        assert!(directory.is_some_and(|d| made.iter().any(|m| m == d)), "{socket} is not in a RuntimeDirectory of the drop-in: {made:?}");
    }
}
