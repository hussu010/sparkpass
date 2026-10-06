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
    /// IP address of the public listener on this host, for example 127.0.0.1. Reconcile sends its
    /// wrong-token check there, with the name of `public_url`.
    pub gateway_check_address: IpAddr,
}

/// Lines `KEY=VALUE`. "#" starts a comment. Unknown keys are ignored. Grant and reconcile read this file.
pub fn read_settings(paths: &Paths) -> Result<Settings, String> {
    let file = paths.config.display();
    let text = fs::read_to_string(&paths.config)
        .map_err(|e| format!("cannot read the settings file {file}: {e}"))?;
    let (mut url, mut port, mut address) = (None, None, None);
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        match line.split_once('=').map(|(key, value)| (key.trim(), value.trim())) {
            Some(("PUBLIC_URL", value)) => url = Some(value.trim_end_matches('/')),
            Some(("MODEL_PORT", value)) => port = value.parse::<u16>().ok().filter(|p| *p > 0),
            Some(("GATEWAY_CHECK_ADDRESS", value)) => address = value.parse::<IpAddr>().ok(),
            _ => {}
        }
    }
    let public_url = url
        // https only: the API key travels in the Authorization header of each request.
        .filter(|u| u.starts_with("https://"))
        .ok_or_else(|| format!("settings file {file}: PUBLIC_URL must start with https://"))?
        .to_string();
    let model_port =
        port.ok_or_else(|| format!("settings file {file}: MODEL_PORT must be a port number"))?;
    let gateway_check_address = address
        .ok_or_else(|| format!("settings file {file}: GATEWAY_CHECK_ADDRESS must be an IP address, for example 127.0.0.1"))?;
    Ok(Settings {
        public_url,
        model_port,
        gateway_check_address,
    })
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
            "# sparkpass settings\n\nPUBLIC_URL = https://spark.example.net/  # public name\nMODEL_PORT=8000\nSSH_BIND=10.0.0.1:2222\nnot a line\nGATEWAY_CHECK_ADDRESS = ::1\n",
        )
        .unwrap();
        assert_eq!((s.public_url.as_str(), s.model_port), ("https://spark.example.net", 8000));
        assert_eq!(s.gateway_check_address, IpAddr::from(std::net::Ipv6Addr::LOCALHOST));
        let s = read_settings(&Paths::temp()).unwrap();
        assert_eq!(s.gateway_check_address, IpAddr::from(std::net::Ipv4Addr::LOCALHOST));
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

    #[test]
    fn settings_file_that_is_missing_is_refused() {
        let paths = Paths::temp();
        fs::remove_file(&paths.config).unwrap();
        assert!(read_settings(&paths).is_err());
    }
}
