//! The gateway (Caddy): the token file, and the commands that close and stop the gateway.

use crate::config::Paths;
use crate::runner::{Runner, run_ok};
use std::fs::{self, File};
use std::io::{self, Read, Write};

/// The content of the token file. This function is the only place that knows the format,
/// because the format can change on the hardware.
/// `None` is the deny-all rule. `Some((name, token))` permits only requests with the token.
pub fn rule(active: Option<(&str, &str)>) -> String {
    match active {
        None => "# sparkpass: deny-all\nrespond 401\n".into(),
        Some((name, token)) => format!(
            "# sparkpass: lease {name}\n@sparkpass_denied not header Authorization \"Bearer {token}\"\nrespond @sparkpass_denied 401\n"
        ),
    }
}

/// Writes the token file in place, so that the owner and the group that install.sh sets stay.
/// The tool never creates the file: a file that root creates has no group that Caddy can read,
/// and the cause would show only in the journal of Caddy.
pub fn write_rule(paths: &Paths, rule: &str) -> io::Result<()> {
    // ponytail: the write is not atomic. A power cut between the truncate and the write leaves an
    // empty file, and a gateway that imports an empty file has no token check. Only the boot gate
    // covers this: reconcile closes the gateway for such a file before it starts the gateway.
    // Upgrade: a Caddyfile that does not load without the rule, or a temporary file with chown and rename.
    let mut file = File::options().write(true).truncate(true).open(&paths.token)?;
    file.write_all(rule.as_bytes())?;
    file.sync_all()
}

pub fn is_deny_all(paths: &Paths) -> bool {
    fs::read_to_string(&paths.token).is_ok_and(|text| text == rule(None))
}

/// The token file is the complete active rule of this lease, with any token.
/// False for the empty or cut file that a power cut in `write_rule` leaves.
pub fn is_rule_of(paths: &Paths, name: &str) -> bool {
    // `rule` stays the only owner of the format: the token is the text between the two fixed parts.
    let frame = rule(Some((name, "\0")));
    let (Ok(text), Some((head, tail))) = (fs::read_to_string(&paths.token), frame.split_once('\0')) else {
        return false;
    };
    text.strip_prefix(head)
        .and_then(|rest| rest.strip_suffix(tail))
        .is_some_and(|token| !token.is_empty() && token.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Test helper: the token in a token file that holds an active rule, of any lease.
/// It lives here so that the tests of other modules do not know the format.
#[cfg(test)]
pub fn token_in(token_file: &std::path::Path) -> Option<String> {
    let text = fs::read_to_string(token_file).ok()?;
    let token = text.split("Bearer ").nth(1)?.split('"').next()?;
    Some(token.to_string())
}

/// 32 random bytes as 64 lower-case hex characters.
pub fn new_token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Closes the gateway: revoke steps 2 and 3. Safe at any time, with or without the lock.
/// Fail closed (eng review D7): if the gateway cannot close in the normal way, it stops.
pub fn close(paths: &Paths, runner: &dyn Runner) -> Result<(), String> {
    // 2. Deny-all rule. If the write failed, a restart can load the old token: stop, do not restart.
    if let Err(e) = write_rule(paths, &rule(None)) {
        return Err(format!("deny-all write to {}: {e}; {}", paths.token.display(), stop(runner)));
    }
    // 3. The restart closes each open connection after the grace period. No effect if Caddy is not active.
    if let Err(e) = run_ok(runner, &["systemctl", "try-restart", "caddy"]) {
        return Err(format!("gateway restart: {e}; {}", stop(runner)));
    }
    Ok(())
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
            "# sparkpass: lease bob\n@sparkpass_denied not header Authorization \"Bearer abc123\"\nrespond @sparkpass_denied 401\n"
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
}
