//! Paths of the state files, the lock, and the settings file.

use std::fs::{self, DirBuilder, File};
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// The end timer calls this binary.
pub const BINARY: &str = "/usr/local/bin/sparkpass";
/// The firewall rules script; grant and reconcile run it. install.sh copies firewall/rules.sh here.
pub const FIREWALL: &str = "/usr/local/lib/sparkpass/rules.sh";

pub struct Paths {
    /// Lease files `<name>.json`. A lease file is the single source of truth.
    pub leases: PathBuf,
    /// Records of ended leases.
    pub history: PathBuf,
    pub lock: PathBuf,
    /// The Caddyfile imports this file. `gateway::rule` owns its format.
    pub token: PathBuf,
    pub config: PathBuf,
    /// Marker of a gateway proven open (an answer other than 401 to a wrong token). While it exists,
    /// reconcile keeps the gateway stopped and grant refuses. The owner removes it after the repair.
    pub gateway_open: PathBuf,
    /// Marker of a model endpoint that was down during a lease, so that one outage sends one notification.
    pub model_down: PathBuf,
    /// Marker of a gateway that reconcile stopped or did not start during a lease (one notification).
    pub gateway_down: PathBuf,
    /// Marker of a sent REVOKE-FAILED notification (one notification for each failed revoke).
    pub revoke_failed: PathBuf,
}

impl Paths {
    /// Production uses the root "/".
    pub fn new(root: &Path) -> Paths {
        let state = root.join("var/lib/sparkpass");
        let etc = root.join("etc/sparkpass");
        Paths {
            leases: state.join("leases"),
            history: state.join("history"),
            lock: state.join("lock"),
            token: etc.join("token.caddy"),
            config: etc.join("config"),
            gateway_open: state.join("gateway-open"),
            model_down: state.join("model-down"),
            gateway_down: state.join("gateway-down"),
            revoke_failed: state.join("revoke-failed"),
        }
    }

    pub fn lease(&self, name: &str) -> PathBuf {
        self.leases.join(format!("{name}.json"))
    }

    /// Takes the exclusive lock and waits until it is free. The lock ends when the file is dropped.
    /// It also creates the state directories, so the tool works before the first grant.
    pub fn lock(&self) -> io::Result<File> {
        for dir in [&self.leases, &self.history] {
            DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        let file = File::options()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock)?;
        file.lock()?;
        Ok(file)
    }
}

pub struct Settings {
    /// For example `https://spark.example.net`, with no trailing slash.
    pub public_url: String,
    /// Port of the model server on 127.0.0.1.
    pub model_port: u16,
    /// 127.0.0.1 ([`CHECK_ADDRESS`]), where Caddy listens (gateway/Caddyfile, `bind`). Grant (steps 1 and 8)
    /// and reconcile send their wrong-token check there, with the name of `public_url`.
    pub gateway_check_address: IpAddr,
}

/// The only valid GATEWAY_CHECK_ADDRESS: the default of `bind` in gateway/Caddyfile (owner decision D3 of
/// the /ship review, 2026-10-07). A test checks the Caddyfile and etc/config.example against it.
pub const CHECK_ADDRESS: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

/// The `KEY=VALUE` lines of the settings file. "#" starts a comment.
fn entries(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.lines()
        .filter_map(|line| line.split('#').next().unwrap_or("").split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
}

/// Lines `KEY=VALUE`. "#" starts a comment. Unknown keys are ignored. Grant and reconcile read this file.
pub fn read_settings(paths: &Paths) -> Result<Settings, String> {
    let file = paths.config.display();
    let text = fs::read_to_string(&paths.config)
        .map_err(|e| format!("cannot read the settings file {file}: {e}"))?;
    let (mut url, mut port, mut address) = (None, None, None);
    for entry in entries(&text) {
        match entry {
            ("PUBLIC_URL", value) => url = Some(value.trim_end_matches('/')),
            ("MODEL_PORT", value) => port = value.parse::<u16>().ok().filter(|p| *p > 0),
            ("GATEWAY_CHECK_ADDRESS", value) => address = value.parse::<IpAddr>().ok(),
            _ => {}
        }
    }
    let public_url = url
        // https only: the API key travels in the Authorization header of each request.
        .filter(|u| u.starts_with("https://"))
        .ok_or_else(|| format!("settings file {file}: PUBLIC_URL must start with https://"))?
        .to_string();
    // A host with a trailing dot (the DNSName of `tailscale status --json` has one) is not the TLS name of
    // Caddy's site: curl sends the Host header with the dot and the TLS name without it, so Caddy answers 421
    // (strict_sni_host) to each request, before the token check, and no pass works.
    if host(&public_url).ends_with('.') {
        return Err(format!(
            "settings file {file}: PUBLIC_URL has a host name with a trailing dot (the DNSName of `tailscale status --json` has one): remove the trailing dot, here and in SPARKPASS_SITE of caddy.env; Caddy answers 421 to each request for such a name"
        ));
    }
    let model_port =
        port.ok_or_else(|| format!("settings file {file}: MODEL_PORT must be a port number"))?;
    // 127.0.0.1 only: the check must reach the Caddy of this host, and Caddy listens only there. Another
    // address can be the other Spark, whose 401 answers would make grant and reconcile trust a local Caddy
    // that is open; another loopback address (::1, 127.0.0.2) has no listener, so each check would fail.
    let gateway_check_address = address.filter(|a| *a == CHECK_ADDRESS).ok_or_else(|| {
        format!("settings file {file}: GATEWAY_CHECK_ADDRESS must be 127.0.0.1, where Caddy listens (bind in gateway/Caddyfile): the check must reach the Caddy of this host, never the other Spark")
    })?;
    Ok(Settings {
        public_url,
        model_port,
        gateway_check_address,
    })
}

/// The host of an `https://` URL, with a user part if it has one: the text up to the path, with no port.
fn host(url: &str) -> &str {
    let authority = url["https://".len()..].split(['/', '?', '#']).next().unwrap_or("");
    // A port is digits after the last ":". Another ":" is no port, for example the ":" of a password in a
    // user part ("u:PASSWORD@host."): without the digit test, the host would be "u".
    authority
        .rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()))
        .map_or(authority, |(host, _)| host)
}

/// NOTIFY_URL of the settings file (owner decision of 2026-10-06), if it is an https URL. It is optional and
/// a secret, so a missing or bad value means no notification, never a failed command.
pub fn notify_url(paths: &Paths) -> Option<String> {
    let text = fs::read_to_string(&paths.config).ok()?;
    let url = entries(&text).filter(|(key, _)| *key == "NOTIFY_URL").last()?.1;
    url.starts_with("https://").then(|| url.to_string())
}

#[cfg(test)]
impl Paths {
    /// A new root for one test, in the state that install.sh leaves:
    /// a deny-all token file, a settings file, and empty state directories.
    pub fn temp() -> Paths {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("sparkpass-test-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let paths = Paths::new(&root);
        fs::create_dir_all(paths.token.parent().unwrap()).unwrap();
        fs::write(&paths.token, crate::gateway::rule(None)).unwrap();
        fs::write(&paths.config, "PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\nGATEWAY_CHECK_ADDRESS=127.0.0.1\n").unwrap();
        drop(paths.lock().unwrap());
        paths
    }

    /// Each file and directory of the state and of /etc/sparkpass, with the file contents.
    pub fn snapshot(&self) -> Vec<(PathBuf, String)> {
        fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    out.push((path.clone(), "<dir>".into()));
                    walk(&path, out);
                } else {
                    out.push((path.clone(), fs::read_to_string(&path).unwrap()));
                }
            }
        }
        let mut out = Vec::new();
        walk(self.lock.parent().unwrap(), &mut out);
        walk(self.token.parent().unwrap(), &mut out);
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn settings(text: &str) -> Result<Settings, String> {
        let paths = Paths::temp();
        fs::write(&paths.config, text).unwrap();
        read_settings(&paths)
    }

    #[test]
    fn paths_are_under_the_root() {
        let paths = Paths::new(Path::new("/"));
        assert_eq!(paths.lease("bob"), Path::new("/var/lib/sparkpass/leases/bob.json"));
        assert_eq!(paths.history, Path::new("/var/lib/sparkpass/history"));
        assert_eq!(paths.lock, Path::new("/var/lib/sparkpass/lock"));
        assert_eq!(paths.token, Path::new("/etc/sparkpass/token.caddy"));
        assert_eq!(paths.config, Path::new("/etc/sparkpass/config"));
        assert_eq!(FIREWALL, "/usr/local/lib/sparkpass/rules.sh");
        // Added by the /ship review (2026-10-06): the markers. tests/expiry.sh writes gateway-open itself,
        // and install.sh names it: grant and reconcile must read that file.
        assert_eq!(paths.gateway_open, Path::new("/var/lib/sparkpass/gateway-open"));
        assert_eq!(paths.model_down, Path::new("/var/lib/sparkpass/model-down"));
        assert_eq!(paths.gateway_down, Path::new("/var/lib/sparkpass/gateway-down"));
        assert_eq!(paths.revoke_failed, Path::new("/var/lib/sparkpass/revoke-failed"));
        let expiry = include_str!("../tests/expiry.sh");
        assert!(expiry.contains("\nSTATE=/var/lib/sparkpass\n") && expiry.contains("\nMARKER=$STATE/gateway-open\n"));
        assert!(include_str!("../install.sh").contains("/var/lib/sparkpass/gateway-open"));
    }

    #[test]
    fn lock_creates_the_state_directories_with_mode_0700() {
        let paths = Paths::temp();
        for dir in [&paths.leases, &paths.history] {
            assert_eq!(fs::metadata(dir).unwrap().permissions().mode() & 0o777, 0o700);
        }
    }

    #[test]
    fn settings_file_is_read() {
        let s = settings(
            "# sparkpass settings\n\nPUBLIC_URL = https://spark.example.net/  # public name\nMODEL_PORT=8000\nSSH_BIND=10.0.0.1:2222\nnot a line\nGATEWAY_CHECK_ADDRESS = 127.0.0.1\n",
        )
        .unwrap();
        assert_eq!((s.public_url.as_str(), s.model_port), ("https://spark.example.net", 8000));
        assert_eq!(s.gateway_check_address, IpAddr::from([127, 0, 0, 1]));
        let s = read_settings(&Paths::temp()).unwrap();
        assert_eq!(s.gateway_check_address, IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn settings_file_with_a_missing_or_bad_value_is_refused() {
        // Each row is refused for the key that it names. A valid address comes first, and a later line replaces it.
        const OK: &str = "PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\n";
        for (text, key) in [
            ("", "PUBLIC_URL"),
            ("PUBLIC_URL=https://spark.example.net\n", "MODEL_PORT"),
            ("MODEL_PORT=8000\n", "PUBLIC_URL"),
            ("PUBLIC_URL=spark.example.net\nMODEL_PORT=8000\n", "PUBLIC_URL"),
            // Plain http would send the API key in clear text.
            ("PUBLIC_URL=http://spark.example.net\nMODEL_PORT=8000\n", "PUBLIC_URL"),
            ("PUBLIC_URL=https://spark.example.net\nMODEL_PORT=0\n", "MODEL_PORT"),
            ("PUBLIC_URL=https://spark.example.net\nMODEL_PORT=70000\n", "MODEL_PORT"),
            ("PUBLIC_URL=https://spark.example.net\nMODEL_PORT=http\n", "MODEL_PORT"),
            ("#PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\n", "PUBLIC_URL"),
            // A name is not an address: the check must reach this host, not what a resolver says.
            (&format!("{OK}GATEWAY_CHECK_ADDRESS=localhost\n"), "GATEWAY_CHECK_ADDRESS"),
            (&format!("{OK}GATEWAY_CHECK_ADDRESS=127.0.0.1:443\n"), "GATEWAY_CHECK_ADDRESS"),
            (&format!("{OK}GATEWAY_CHECK_ADDRESS=[::1]\n"), "GATEWAY_CHECK_ADDRESS"),
            (&format!("{OK}GATEWAY_CHECK_ADDRESS=127.0.0.256\n"), "GATEWAY_CHECK_ADDRESS"),
            (&format!("{OK}GATEWAY_CHECK_ADDRESS=\n"), "GATEWAY_CHECK_ADDRESS"),
        ] {
            let error = settings(&format!("GATEWAY_CHECK_ADDRESS=127.0.0.1\n{text}")).err().unwrap_or_default();
            assert!(error.contains(key), "{text:?}: {error}");
        }
        // No address line.
        let error = settings(OK).err().unwrap_or_default();
        assert!(error.contains("GATEWAY_CHECK_ADDRESS"), "{error}");
    }

    // Added for the P1 item "Prove the gateway step on the units" (2026-10-07); extended by the /ship review
    // (owner decision D3): other loopback addresses too.
    // Value: protects=the wrong-key check of grant and reconcile reaches the Caddy of this host, where it
    // listens; fails_when=read_settings accepts the other Spark (its 401 answers would make reconcile trust a
    // local Caddy that is open) or a loopback address with no listener (each check fails with no reason given);
    // why_new=each IP address passed, then each loopback address; seam=none
    #[test]
    fn settings_file_with_a_check_address_other_than_127_0_0_1_is_refused() {
        // A LAN or QSFP address (the other Spark), a wildcard, a public, a link-local and an IPv4-mapped address,
        // and loopback addresses where Caddy does not listen (QA of 2026-10-07: [::1] gets "connection refused").
        for address in [
            "192.168.1.20", "10.0.0.2", "0.0.0.0", "::", "2001:db8::5", "169.254.1.1", "::ffff:127.0.0.1", "100.101.102.103",
            "::1", "127.0.0.2", "127.1.2.3", "0:0:0:0:0:0:0:1",
        ] {
            let error = settings(&format!("PUBLIC_URL=https://spark.example.net\nMODEL_PORT=8000\nGATEWAY_CHECK_ADDRESS={address}\n"))
                .err()
                .unwrap_or_default();
            assert!(
                error.contains("GATEWAY_CHECK_ADDRESS must be 127.0.0.1, where Caddy listens") && error.contains("never the other Spark"),
                "{address}: {error}"
            );
        }
    }

    // Added by the /ship review (2026-10-07, owner decision D3).
    // Value: protects=the one valid check address, the listen address of gateway/Caddyfile and the value of
    // etc/config.example are the same; fails_when=one of the three changes alone, and each check of grant and
    // reconcile then gets "connection refused"; why_new=the bind default is new on this branch; seam=none
    #[test]
    fn check_address_is_the_listen_address_of_the_caddyfile_and_of_the_example() {
        let bind = include_str!("../gateway/Caddyfile")
            .lines()
            .find_map(|line| line.trim().strip_prefix("bind {$SPARKPASS_BIND:")?.strip_suffix('}'))
            .expect("gateway/Caddyfile has no bind line with a default");
        let example = include_str!("../etc/config.example")
            .lines()
            .find_map(|line| line.strip_prefix("GATEWAY_CHECK_ADDRESS="))
            .expect("etc/config.example has no GATEWAY_CHECK_ADDRESS line");
        assert_eq!((bind, example), ("127.0.0.1", "127.0.0.1"));
        assert_eq!(CHECK_ADDRESS.to_string(), bind);
    }

    // Added for the TODO item "Review follow-ups of the Funnel branch", item 5 (2026-10-08).
    // Value: protects=a PUBLIC_URL host with a trailing dot (the DNSName of `tailscale status --json`) is
    // refused with the fix in the message; fails_when=read_settings accepts it: each check then gets 421 from
    // strict_sni_host, and no pass works; why_new=each https URL passed; seam=none
    #[test]
    fn settings_file_with_a_trailing_dot_in_the_public_host_is_refused() {
        const REST: &str = "MODEL_PORT=8000\nGATEWAY_CHECK_ADDRESS=127.0.0.1\n";
        for url in [
            "https://spark.tail1234.ts.net.",
            "https://spark.tail1234.ts.net./",
            "https://spark.example.net.:443",
            "https://spark.example.net./api",
            "https://u@spark.example.net.",
            "https://u:PASSWORD@spark.example.net.",
        ] {
            let error = settings(&format!("PUBLIC_URL={url}\n{REST}")).err().unwrap_or_default();
            assert!(error.contains("PUBLIC_URL has a host name with a trailing dot") && error.contains("remove the trailing dot"), "{url}: {error}");
        }
        // A dot elsewhere is no trailing dot: a port, a path, an IPv6 literal, a user part.
        for url in ["https://spark.example.net:8443", "https://spark.example.net/v.", "https://[2001:db8::5]:8443", "https://[2001:db8::5]", "https://u.@spark.example.net"] {
            assert!(settings(&format!("PUBLIC_URL={url}\n{REST}")).is_ok(), "{url}");
        }
    }

    #[test]
    fn settings_file_that_is_missing_is_refused() {
        let paths = Paths::temp();
        fs::remove_file(&paths.config).unwrap();
        assert!(read_settings(&paths).is_err());
    }
}
