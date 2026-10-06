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

// Value: protects=a failed write of the stdout text gives exit code 1 and a stderr text, not a panic of println! (exit code 101);
// fails_when=main writes the text with println!, or ignores the write error and gives exit code 0;
// why_new=only the binary has the real stdout; the unit test of write_text does not reach main; seam=none
#[test]
fn failed_write_of_the_output_gives_exit_code_1_and_a_stderr_text() {
    // `list` takes no lock and writes no file. Each write to /dev/full fails (Linux only, as the units and CI).
    // `list` reads the real state directory: on a host with sparkpass installed, a user that is not root
    // gets a read error before the write, so this part runs only where the state directory does not exist.
    if !std::path::Path::new("/var/lib/sparkpass").exists() {
        let full = std::fs::File::options().write(true).open("/dev/full").unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_sparkpass")).arg("list").stdout(full).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(stderr.starts_with("sparkpass: the command completed, but its output was not written: "), "{stderr}");
    }

    // A failed write to stderr also: the exit code stays, and eprintln! would panic (exit code 101).
    for (args, code) in [(&["list"][..], 1), (&[][..], 2)] {
        let full = || std::fs::File::options().write(true).open("/dev/full").unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_sparkpass")).args(args).stdout(full()).stderr(full()).output().unwrap();
        assert_eq!(out.status.code(), Some(code), "{args:?}");
    }
}
