//! The command runner: the only abstraction of the crate. Each system command goes through it,
//! so that the unit tests run with fake commands and no hardware.

use std::fmt;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct Output {
    /// `None`: a signal ended the command.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RunError {
    /// The command did not start.
    Spawn(String),
    /// The command gave no result in the time limit.
    Timeout(Duration),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RunError::Spawn(e) => write!(f, "the command did not start: {e}"),
            RunError::Timeout(limit) => write!(f, "no result after {limit:?}"),
        }
    }
}

pub trait Runner: Sync {
    fn run(&self, argv: &[&str]) -> Result<Output, RunError>;
}

pub fn exit_text(code: Option<i32>) -> String {
    code.map_or("ended by a signal".into(), |c| format!("exit code {c}"))
}

/// Runs a command that must end with exit code 0.
/// The error text holds the argv. Do not use this function for an argv that holds the token.
pub fn run_ok(runner: &dyn Runner, argv: &[&str]) -> Result<Output, String> {
    match runner.run(argv) {
        Ok(out) if out.code == Some(0) => Ok(out),
        Ok(out) => Err(format!(
            "`{}`: {}: {}",
            argv.join(" "),
            exit_text(out.code),
            // One line: the text goes to the journal, and the journal makes one record for each line.
            out.stderr.trim().replace('\n', " ")
        )),
        Err(e) => Err(format!("`{}`: {e}", argv.join(" "))),
    }
}

/// The part of each pipe that `RealRunner` keeps in memory: a broken command must not exhaust it.
const PIPE_LIMIT: u64 = 1 << 20;

pub struct RealRunner {
    /// Time limit for each command. A command that hangs must not hold the lock without end.
    pub limit: Duration,
}

impl Runner for RealRunner {
    fn run(&self, argv: &[&str]) -> Result<Output, RunError> {
        let Some((program, args)) = argv.split_first() else {
            return Err(RunError::Spawn("empty command".into()));
        };
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| RunError::Spawn(e.to_string()))?;
        // Reader threads: a child with much output must not block on a full pipe.
        let (stdout, stderr) = (drain(child.stdout.take()), drain(child.stderr.take()));
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // The rest of the one limit applies here: a grandchild can hold a pipe open after the child ended.
                    let read = |pipe: Receiver<String>| {
                        pipe.recv_timeout(self.limit.saturating_sub(start.elapsed()))
                            .map_err(|_| RunError::Timeout(self.limit))
                    };
                    return Ok(Output {
                        code: status.code(),
                        stdout: read(stdout)?,
                        stderr: read(stderr)?,
                    });
                }
                Ok(None) if start.elapsed() < self.limit => thread::sleep(Duration::from_millis(10)),
                // The limit is over, or the child state is unknown.
                _ => {
                    // ponytail: only the direct child is killed. A grandchild continues to run.
                    // Upgrade: start the child in its own process group and kill the group (needs libc).
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(RunError::Timeout(self.limit));
                }
            }
        }
    }
}

fn drain(pipe: Option<impl Read + Send + 'static>) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.by_ref().take(PIPE_LIMIT).read_to_end(&mut bytes);
            // The rest is read and discarded: the child must not block on a full pipe.
            let _ = io::copy(&mut pipe, &mut io::sink());
        }
        let _ = tx.send(String::from_utf8_lossy(&bytes).into_owned());
    });
    rx
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::sync::Mutex;

    type Hook = Box<dyn Fn(&[&str]) + Send>;

    /// Records each argv. Returns exit code 0 with empty output, or the scripted result.
    #[derive(Default)]
    pub struct FakeRunner {
        calls: Mutex<Vec<Vec<String>>>,
        script: Mutex<Vec<(String, Result<Output, RunError>)>>,
        hook: Mutex<Option<Hook>>,
        /// `healthy()` only: is an end timer active? `None`: each command gives exit code 0.
        /// ponytail: one state for all units, because one guest has access at a time.
        timer: Mutex<Option<bool>>,
    }

    pub fn output(code: i32, stdout: &str) -> Result<Output, RunError> {
        Ok(Output {
            code: Some(code),
            stdout: stdout.into(),
            stderr: String::new(),
        })
    }

    impl FakeRunner {
        /// A host in the normal state: the model answers, and no end timer is active.
        /// `systemd-run` makes the end timer active, and `systemctl stop <unit>.timer` ends it.
        pub fn healthy() -> FakeRunner {
            let runner = FakeRunner { timer: Mutex::new(Some(false)), ..FakeRunner::default() };
            runner.on("curl -q --noproxy * -fsS -m 8 http://127.0.0.1:8000/v1/models", output(0, r#"{"object":"list","data":[{"id":"test-model"}]}"#));
            // The gateway accepts the pass key and refuses the wrong key of grant (the newer rule wins).
            runner.on("curl -q --noproxy * -sS -o /dev/null -m 8 -w %{http_code} -H Authorization: Bearer ", output(0, "200"));
            runner.on(&format!("curl -q --noproxy * -sS -o /dev/null -m 8 -w %{{http_code}} -H Authorization: Bearer {}", "0".repeat(64)), output(0, "401"));
            // The public listener at GATEWAY_CHECK_ADDRESS refuses the wrong token of the reconcile check.
            runner.on("curl -q --noproxy * -sS -o /dev/null -m 8 -w %{http_code} --connect-to ", output(0, "401"));
            runner
        }

        /// Scripts the result of each command whose joined argv starts with `prefix`. The newest rule wins.
        pub fn on(&self, prefix: &str, result: Result<Output, RunError>) {
            self.script.lock().unwrap().push((prefix.into(), result));
        }

        pub fn exit(&self, prefix: &str, code: i32) {
            self.on(prefix, output(code, ""));
        }

        /// `hook` runs at each command, after the record and before the result.
        pub fn hook(&self, hook: impl Fn(&[&str]) + Send + 'static) {
            *self.hook.lock().unwrap() = Some(Box::new(hook));
        }

        pub fn argv(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }

        pub fn calls(&self) -> Vec<String> {
            self.argv().iter().map(|argv| argv.join(" ")).collect()
        }

        pub fn count(&self, prefix: &str) -> usize {
            self.calls().iter().filter(|call| call.starts_with(prefix)).count()
        }
    }

    impl Runner for FakeRunner {
        fn run(&self, argv: &[&str]) -> Result<Output, RunError> {
            self.calls
                .lock()
                .unwrap()
                .push(argv.iter().map(|arg| arg.to_string()).collect());
            if let Some(hook) = &*self.hook.lock().unwrap() {
                hook(argv);
            }
            let joined = argv.join(" ");
            let script = self.script.lock().unwrap();
            if let Some((_, result)) = script.iter().rev().find(|(prefix, _)| joined.starts_with(prefix)) {
                return result.clone();
            }
            if let Some(active) = self.timer.lock().unwrap().as_mut() {
                match argv {
                    ["systemd-run", ..] => *active = true,
                    ["systemctl", "stop", unit] if unit.ends_with(".timer") => *active = false,
                    // systemctl gives 3 for a unit that is not active.
                    ["systemctl", "is-active", "--quiet", unit] if unit.ends_with(".timer") && !*active => return output(3, ""),
                    _ => {}
                }
            }
            output(0, "")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{FakeRunner, output};
    use super::*;

    fn real(limit_ms: u64) -> RealRunner {
        RealRunner {
            limit: Duration::from_millis(limit_ms),
        }
    }

    #[test]
    fn real_runner_returns_the_output_of_a_short_command() {
        let out = real(10_000).run(&["sh", "-c", "echo out; echo err >&2"]).unwrap();
        assert_eq!(out, Output { code: Some(0), stdout: "out\n".into(), stderr: "err\n".into() });
    }

    // Extended by the /ship test coverage audit (2026-10-06): the signal part.
    // Value: protects=RealRunner gives code None, not a number, for a child that a signal ended;
    // fails_when=a signal death becomes an exit code (0 or 128+n), and end_timer_exists reads a killed check as "no timer";
    // why_new=the callers got code None only from the fake runner; no test made a real signal death; seam=none
    #[test]
    fn real_runner_returns_a_non_zero_exit_code_and_none_after_a_signal() {
        let out = real(10_000).run(&["sh", "-c", "exit 3"]).unwrap();
        assert_eq!(out.code, Some(3));
        // SIGKILL ends the shell: there is no exit code, and a caller must not get a number for it.
        let out = real(10_000).run(&["sh", "-c", "kill -9 $$"]).unwrap();
        assert_eq!(out.code, None);
    }

    #[test]
    fn real_runner_reports_a_missing_binary() {
        let result = real(10_000).run(&["/nonexistent/sparkpass-no-such-binary"]);
        assert!(matches!(result, Err(RunError::Spawn(_))), "{result:?}");
        assert!(matches!(real(10_000).run(&[]), Err(RunError::Spawn(_))));
    }

    #[test]
    fn real_runner_stops_a_command_that_hangs() {
        let pid_file = std::env::temp_dir().join(format!("sparkpass-test-pid-{}", std::process::id()));
        let start = Instant::now();
        // `exec`: sleep is the direct child, with the PID that the shell wrote.
        let script = "echo $$ > \"$0\"; exec sleep 30";
        let result = real(300).run(&["sh", "-c", script, pid_file.to_str().unwrap()]);
        assert_eq!(result, Err(RunError::Timeout(Duration::from_millis(300))));
        assert!(start.elapsed() < Duration::from_secs(3), "{:?}", start.elapsed());
        // Killed and waited for: a child that runs has an entry in /proc, and a zombie has one also.
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        assert!(!std::path::Path::new("/proc").join(pid.trim()).exists(), "the child {pid} is not gone");
    }

    #[test]
    fn real_runner_has_one_limit_for_the_child_and_its_pipes() {
        // The child ends after 0.7 s. A grandchild holds the pipes open for longer than the limit.
        let start = Instant::now();
        let result = real(1_000).run(&["sh", "-c", "sleep 5 & sleep 0.7"]);
        assert_eq!(result, Err(RunError::Timeout(Duration::from_secs(1))));
        // A new limit for each pipe gives 1.7 s or more.
        assert!(start.elapsed() < Duration::from_millis(1_500), "{:?}", start.elapsed());
    }

    #[test]
    fn real_runner_reads_200_kb_on_each_pipe_without_a_deadlock() {
        let script = "head -c 200000 /dev/zero | tr '\\0' x; head -c 200000 /dev/zero | tr '\\0' y >&2";
        let out = real(20_000).run(&["sh", "-c", script]).unwrap();
        assert_eq!(out.code, Some(0));
        assert_eq!(out.stdout, "x".repeat(200_000));
        assert_eq!(out.stderr, "y".repeat(200_000));
    }

    #[test]
    fn real_runner_keeps_the_first_1_mib_of_each_pipe_and_discards_the_rest() {
        // 2 MiB on each pipe: 1 MiB of x, then 1 MiB of z.
        let script = "for c in x z; do head -c 1048576 /dev/zero | tr '\\0' $c; head -c 1048576 /dev/zero | tr '\\0' $c >&2; done";
        // A result in the limit: the child did not block on a full pipe after the first 1 MiB.
        let out = real(20_000).run(&["sh", "-c", script]).unwrap();
        assert_eq!(out.code, Some(0));
        assert!(out.stdout == "x".repeat(1 << 20), "stdout has {} bytes", out.stdout.len());
        assert!(out.stderr == "x".repeat(1 << 20), "stderr has {} bytes", out.stderr.len());
    }

    #[test]
    fn real_runner_gives_the_child_no_stdin() {
        // The stdin of `cargo test` can be /dev/null already, and then `cat` proves nothing.
        // Thus the test starts itself again with a stdin pipe that stays open.
        const GUARD: &str = "SPARKPASS_TEST_OPEN_STDIN";
        if std::env::var_os(GUARD).is_none() {
            let mut again = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "runner::tests::real_runner_gives_the_child_no_stdin"])
                .env(GUARD, "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            // `wait` closes a stdin that the Child still owns.
            let _open = again.stdin.take();
            assert!(again.wait().unwrap().success());
            return;
        }
        // With an open stdin, `cat` waits for input until the limit.
        assert_eq!(real(5_000).run(&["cat"]), output(0, ""));
    }

    #[test]
    fn run_ok_accepts_only_exit_code_0() {
        let runner = FakeRunner::default();
        assert_eq!(run_ok(&runner, &["true"]), Ok(output(0, "").unwrap()));
        runner.on("systemctl", Ok(Output { code: Some(5), stdout: String::new(), stderr: "no such unit\n".into() }));
        assert_eq!(
            run_ok(&runner, &["systemctl", "start", "caddy"]),
            Err("`systemctl start caddy`: exit code 5: no such unit".into())
        );
        // The error text is one line, also for the usual two-line text of systemctl.
        let stderr = "Job for caddy.service failed.\nSee \"systemctl status caddy.service\" for details.\n";
        runner.on("systemctl", Ok(Output { code: Some(1), stdout: String::new(), stderr: stderr.into() }));
        assert_eq!(
            run_ok(&runner, &["systemctl", "start", "caddy"]),
            Err("`systemctl start caddy`: exit code 1: Job for caddy.service failed. See \"systemctl status caddy.service\" for details.".into())
        );
        runner.on("systemctl", Err(RunError::Timeout(Duration::from_secs(10))));
        assert_eq!(
            run_ok(&runner, &["systemctl", "start", "caddy"]),
            Err("`systemctl start caddy`: no result after 10s".into())
        );
        runner.on("systemctl", Ok(Output { code: None, stdout: String::new(), stderr: String::new() }));
        assert!(run_ok(&runner, &["systemctl", "start", "caddy"]).is_err());
    }

    #[test]
    fn fake_runner_records_and_the_newest_rule_wins() {
        let runner = FakeRunner::healthy();
        assert_eq!(runner.run(&["systemctl", "is-active", "--quiet", "x.timer"]).unwrap().code, Some(3));
        // Only timer units follow the timer model; caddy is active on a healthy host.
        assert_eq!(runner.run(&["systemctl", "is-active", "--quiet", "caddy"]).unwrap().code, Some(0));
        runner.exit("systemctl is-active", 0);
        assert_eq!(runner.run(&["systemctl", "is-active", "--quiet", "x.timer"]).unwrap().code, Some(0));
        assert_eq!(runner.run(&["other"]), output(0, ""));
        assert_eq!(
            runner.calls(),
            ["systemctl is-active --quiet x.timer", "systemctl is-active --quiet caddy", "systemctl is-active --quiet x.timer", "other"]
        );
        assert_eq!(runner.count("systemctl is-active"), 3);
    }
}
