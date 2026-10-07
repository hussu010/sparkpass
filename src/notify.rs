//! Owner notification (owner decision of 2026-10-06): one plain-text POST to NOTIFY_URL of the settings
//! file, for example an ntfy topic. The URL is a secret, so no error text holds it.

use crate::config::{self, Paths};
use crate::runner::{Runner, exit_text};
use std::io::{self, Write};

/// The longest text of one message, in bytes.
const TEXT_LIMIT: usize = 3500;

/// Sends `text`. No NOTIFY_URL means no message. A failed send goes only to the journal: a notification
/// must never change the result of a command. True only for a sent message, so that a notification
/// marker never stands for a message that did not go (also with no NOTIFY_URL, or a settings file that
/// cannot be read).
pub fn send(paths: &Paths, runner: &dyn Runner, text: &str) -> bool {
    let Some(url) = config::notify_url(paths) else {
        return false;
    };
    // The error texts can hold a long stderr. Linux refuses one argument over 128 KiB, and an ntfy server
    // can refuse a body over 4 KiB: cut the text at a character boundary.
    let mut end = text.len().min(TEXT_LIMIT);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let text = &text[..end];
    // -q first: root's ~/.curlrc cannot change the request. A proxy from the environment is allowed,
    // because the message goes to the internet.
    // ponytail: the URL is in the argv, thus in the process list for the time of the send, as the token is
    // in grant's self-check. The host has one owner. Upgrade: give curl the URL in a root-only file (-K).
    // -w after the URL: a redirect (3xx) gives exit code 0 with no message delivered, so only an HTTP
    // 2xx answer counts as sent (review of 2026-10-06).
    let failure = match runner.run(&["curl", "-q", "-fsS", "-o", "/dev/null", "-m", crate::grant::CURL_LIMIT, "--data-binary", text, &url, "-w", "%{http_code}"]) {
        Ok(out) if out.code == Some(0) && out.stdout.trim().starts_with('2') => return true,
        Ok(out) if out.code == Some(0) => format!("HTTP {}, not 2xx", out.stdout.trim()),
        Ok(out) => exit_text(out.code),
        Err(e) => e.to_string(),
    };
    // Not eprintln!: a failed write to stderr must not panic.
    let _ = writeln!(io::stderr(), "sparkpass: the notification was not sent: curl {failure}");
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::{FakeRunner, output};
    use std::fs;

    const URL: &str = "https://ntfy.example.net/secret-topic";

    #[test]
    fn notification_posts_the_text_to_notify_url_only_when_it_is_set_and_https() {
        for (settings, sent) in [
            (format!("NOTIFY_URL={URL}\n"), true),
            (format!("NOTIFY_URL = {URL}  # the topic\n"), true),
            ("".to_string(), false),
            ("NOTIFY_URL=http://ntfy.example.net/topic\n".to_string(), false),
            ("#NOTIFY_URL=https://ntfy.example.net/topic\n".to_string(), false),
            ("NOTIFY_URL=\n".to_string(), false),
        ] {
            let (paths, runner) = (Paths::temp(), FakeRunner::default());
            runner.on("curl", output(0, "200"));
            fs::write(&paths.config, format!("PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\n{settings}")).unwrap();
            // True only for a sent message (review of 2026-10-06): a marker must not stand for no message.
            assert_eq!(send(&paths, &runner, "lease bob is REVOKE-FAILED"), sent, "{settings:?}");
            let expected: Vec<String> = if sent {
                vec![format!("curl -q -fsS -o /dev/null -m 8 --data-binary lease bob is REVOKE-FAILED {URL} -w %{{http_code}}")]
            } else {
                vec![]
            };
            assert_eq!(runner.calls(), expected, "{settings:?}");
        }
    }

    #[test]
    fn failed_notification_changes_nothing() {
        let (paths, runner) = (Paths::temp(), FakeRunner::default());
        fs::write(&paths.config, format!("NOTIFY_URL={URL}\n")).unwrap();
        runner.on("curl", output(22, ""));
        let before = paths.snapshot();
        assert!(!send(&paths, &runner, "text"));
        assert_eq!(paths.snapshot(), before);
        assert_eq!(runner.count("curl"), 1);
    }

    // Added by the /ship review, Step 11 (2026-10-06).
    // Value: protects=a long error text still gives a message (Linux refuses one argument over 128 KiB, an
    // ntfy server can refuse a body over 4 KiB); fails_when=the cut goes, or it cuts inside a character
    // (a panic); why_new=each test had a short text; seam=none
    #[test]
    fn long_text_is_cut_at_a_character_boundary() {
        let (paths, runner) = (Paths::temp(), FakeRunner::default());
        runner.on("curl", output(0, "200"));
        fs::write(&paths.config, format!("NOTIFY_URL={URL}\n")).unwrap();
        // "é" is 2 bytes: 1 + 2 * 1749 = 3499 bytes, and the next character crosses the limit.
        let text = format!("x{}{}", "é".repeat(1_749), "é".repeat(100_000));
        assert!(send(&paths, &runner, &text));
        let argv = runner.argv();
        let sent = &argv[0][argv[0].len() - 4];
        assert_eq!(sent.len(), 3_499);
        assert!(text.starts_with(sent.as_str()));
    }

    // Added by the /ship review, Step 11 round 2 (2026-10-06).
    // Value: protects=only an HTTP 2xx answer counts as sent, so a marker never stands for a message that a
    // redirect lost; fails_when=exit code 0 alone counts as sent (curl -f fails only for 400 and above);
    // why_new=each test had a 200 answer or a curl failure; seam=none
    #[test]
    fn redirect_or_an_answer_with_no_code_is_not_a_sent_message() {
        for (answer, sent) in [("200", true), ("204", true), ("301", false), ("308", false), ("", false)] {
            let (paths, runner) = (Paths::temp(), FakeRunner::default());
            runner.on("curl", output(0, answer));
            fs::write(&paths.config, format!("NOTIFY_URL={URL}\n")).unwrap();
            assert_eq!(send(&paths, &runner, "text"), sent, "{answer:?}");
        }
    }
}
