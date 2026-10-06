//! The `sparkpass` binary at its process boundary. The unit tests in src/ call `run`, not `main`.

use std::process::Command;

// Added by the /ship test coverage audit (2026-10-06).
// Value: protects=an error from run() reaches the caller of the binary as stderr text and as its exit code (2 = usage error);
// fails_when=main prints the error to stdout, or gives exit code 0 or 1 for a usage error;
// why_new=the unit tests stop at run(), and no test starts the binary; seam=none
#[test]
fn usage_error_goes_to_stderr_with_exit_code_2() {
    // Only the call with no arguments: it can never become a command that changes the host,
    // and main refuses it before it touches a file or starts a command.
    let out = Command::new(env!("CARGO_BIN_EXE_sparkpass")).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "{:?}", String::from_utf8_lossy(&out.stdout));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.starts_with("sparkpass: usage:"), "{stderr}");
}
