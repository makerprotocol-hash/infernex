//! Fail-closed local management of explicitly authorized IPs, CIDRs, and exact hostnames.
//! No DNS, networking, probing, or subprocess execution is performed.
//!
//! Storage is UTF-8 text with one normalized record per line. Blank lines and
//! comment lines are ignored. Any malformed record fails the complete read;
//! corrupt storage is never silently treated as an empty authorization list.
//! Set INFERNEX_SCOPE_FILE to override the default per-user storage location.

use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const HEADER: &str = "# INFERNEX authorized scope v1";
static TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// A normalized authorized scope record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ScopeEntry {
    /// One exact IPv4 or IPv6 address.
    Ip(IpAddr),
    /// A canonical IPv4 or IPv6 network.
    Network(IpNetwork),
    /// One exact lowercase ASCII hostname.
    Hostname(String),
}

impl fmt::Display for ScopeEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Network(net) => write!(f, "{net}"),
            Self::Hostname(host) => f.write_str(host),
        }
    }
}

/// A canonical IP network.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IpNetwork {
    address: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    /// Canonical network address.
    pub fn address(&self) -> IpAddr { self.address }
    /// Prefix length.
    pub fn prefix(&self) -> u8 { self.prefix }

    /// Whether an address belongs to this network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mask = mask4(self.prefix);
                u32::from(a) & mask == u32::from(b) & mask
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let mask = mask6(self.prefix);
                u128::from(a) & mask == u128::from(b) & mask
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

/// Typed errors for validation, inventory operations, and persistence.
#[derive(Debug)]
pub enum ScopeError {
    /// Input is not a supported address, CIDR, or hostname.
    InvalidEntry(String),
    /// The normalized entry already exists.
    DuplicateEntry(String),
    /// The normalized entry does not exist.
    EntryNotFound(String),
    /// Stored data contains an invalid line.
    CorruptStorage { line: usize, value: String, reason: String },
    /// A filesystem operation failed.
    Io(io::Error),
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEntry(v) => write!(f, "invalid scope entry '{v}'"),
            Self::DuplicateEntry(v) => write!(f, "scope entry already exists: {v}"),
            Self::EntryNotFound(v) => write!(f, "scope entry not found: {v}"),
            Self::CorruptStorage { line, value, reason } =>
                write!(f, "corrupt scope storage at line {line} ('{value}'): {reason}"),
            Self::Io(e) => write!(f, "scope storage error: {e}"),
        }
    }
}

impl Error for ScopeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self { Self::Io(e) => Some(e), _ => None }
    }
}
impl From<io::Error> for ScopeError {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}

/// Persistent local scope inventory.
#[derive(Clone, Debug)]
pub struct ScopeManager {
    path: PathBuf,
}

impl ScopeManager {
    /// Opens the default per-user file, honoring INFERNEX_SCOPE_FILE.
    pub fn open_default() -> Result<Self, ScopeError> {
        Ok(Self { path: default_path()? })
    }

    /// Creates a manager using an explicit path.
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Returns the storage path.
    pub fn storage_path(&self) -> &Path { &self.path }

    /// Validates, normalizes, and persistently adds an entry.
    pub fn add(&self, value: &str) -> Result<ScopeEntry, ScopeError> {
        let entry = parse_entry(value)?;
        let mut entries = self.read()?;
        if !entries.insert(entry.clone()) {
            return Err(ScopeError::DuplicateEntry(entry.to_string()));
        }
        self.write(&entries)?;
        Ok(entry)
    }

    /// Removes an entry using the same normalization rules as add.
    pub fn remove(&self, value: &str) -> Result<ScopeEntry, ScopeError> {
        let entry = parse_entry(value)?;
        let mut entries = self.read()?;
        if !entries.remove(&entry) {
            return Err(ScopeError::EntryNotFound(entry.to_string()));
        }
        self.write(&entries)?;
        Ok(entry)
    }

    /// Lists normalized entries in deterministic order.
    pub fn list(&self) -> Result<Vec<ScopeEntry>, ScopeError> {
        Ok(self.read()?.into_iter().collect())
    }

    /// Checks a candidate. Valid but unlisted targets return false.
    /// Invalid targets and corrupt storage return errors. Hostnames match
    /// exactly; no DNS resolution or subdomain inference is performed.
    pub fn check(&self, target: &str) -> Result<bool, ScopeError> {
        let target = parse_target(target)?;
        let entries = self.read()?;
        Ok(match target {
            ScopeEntry::Ip(ip) => entries.iter().any(|entry| match entry {
                ScopeEntry::Ip(allowed) => *allowed == ip,
                ScopeEntry::Network(net) => net.contains(ip),
                ScopeEntry::Hostname(_) => false,
            }),
            ScopeEntry::Hostname(host) => entries.contains(&ScopeEntry::Hostname(host)),
            ScopeEntry::Network(_) => false,
        })
    }

    fn read(&self) -> Result<BTreeSet<ScopeEntry>, ScopeError> {
        let data = match fs::read_to_string(&self.path) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
            Err(e) => return Err(e.into()),
        };
        let mut entries = BTreeSet::new();
        for (index, raw) in data.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() { continue; }
            if line.starts_with("# INFERNEX authorized scope ") && line != HEADER {
                return Err(ScopeError::CorruptStorage {
                    line: index + 1,
                    value: line.to_owned(),
                    reason: "unsupported scope storage format version".into(),
                });
            }
            if line.starts_with('#') { continue; }
            let entry = parse_entry(line).map_err(|e| ScopeError::CorruptStorage {
                line: index + 1, value: line.to_owned(), reason: e.to_string(),
            })?;
            if !entries.insert(entry.clone()) {
                return Err(ScopeError::CorruptStorage {
                    line: index + 1,
                    value: line.to_owned(),
                    reason: format!("duplicate normalized entry '{entry}'"),
                });
            }
        }
        Ok(entries)
    }

    fn write(&self, entries: &BTreeSet<ScopeEntry>) -> Result<(), ScopeError> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let mut data = format!("{HEADER}\n");
        for entry in entries {
            data.push_str(&entry.to_string());
            data.push('\n');
        }
        atomic_replace(&self.path, data.as_bytes())?;
        Ok(())
    }
}

/// Adds to the default per-user inventory.
pub fn add(value: &str) -> Result<ScopeEntry, ScopeError> {
    ScopeManager::open_default()?.add(value)
}
/// Removes from the default per-user inventory.
pub fn remove(value: &str) -> Result<ScopeEntry, ScopeError> {
    ScopeManager::open_default()?.remove(value)
}
/// Lists the default per-user inventory.
pub fn list() -> Result<Vec<ScopeEntry>, ScopeError> {
    ScopeManager::open_default()?.list()
}
/// Checks against the default per-user inventory; deny by default.
pub fn check(target: &str) -> Result<bool, ScopeError> {
    ScopeManager::open_default()?.check(target)
}

/// Parses and normalizes an IP, CIDR, or exact hostname.
pub fn parse_entry(value: &str) -> Result<ScopeEntry, ScopeError> {
    let input = value.trim();
    if input.is_empty() || input.contains('*') || input.contains('?')
        || (input.contains('/') && input.matches('/').count() != 1) {
        return Err(ScopeError::InvalidEntry(value.to_owned()));
    }
    if input.contains('/') {
        let (address, bits) = input.split_once('/').expect("slash count checked");
        if bits.is_empty() || !bits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ScopeError::InvalidEntry(value.to_owned()));
        }
        let ip = IpAddr::from_str(address)
            .map_err(|_| ScopeError::InvalidEntry(value.to_owned()))?;
        let prefix = bits.parse::<u8>()
            .map_err(|_| ScopeError::InvalidEntry(value.to_owned()))?;
        let network = match ip {
            IpAddr::V4(ip) if prefix <= 32 => IpNetwork {
                address: IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask4(prefix))),
                prefix,
            },
            IpAddr::V6(ip) if prefix <= 128 => IpNetwork {
                address: IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask6(prefix))),
                prefix,
            },
            _ => return Err(ScopeError::InvalidEntry(value.to_owned())),
        };
        // A host-length CIDR is the same authorization as an exact IP.
        // Store it as Ip so duplicate detection is semantic, not just textual.
        if (matches!(network.address, IpAddr::V4(_)) && prefix == 32)
            || (matches!(network.address, IpAddr::V6(_)) && prefix == 128)
        {
            return Ok(ScopeEntry::Ip(network.address));
        }
        return Ok(ScopeEntry::Network(network));
    }
    if let Ok(ip) = IpAddr::from_str(input) { return Ok(ScopeEntry::Ip(ip)); }
    normalize_host(input)
        .map(ScopeEntry::Hostname)
        .ok_or_else(|| ScopeError::InvalidEntry(value.to_owned()))
}

fn parse_target(value: &str) -> Result<ScopeEntry, ScopeError> {
    let input = value.trim();
    if input.contains('/') { return Err(ScopeError::InvalidEntry(value.to_owned())); }
    if let Ok(ip) = IpAddr::from_str(input) { return Ok(ScopeEntry::Ip(ip)); }
    normalize_host(input)
        .map(ScopeEntry::Hostname)
        .ok_or_else(|| ScopeError::InvalidEntry(value.to_owned()))
}

fn normalize_host(value: &str) -> Option<String> {
    let host = value.strip_suffix('.').unwrap_or(value);
    if host.ends_with('.') || host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return None;
    }
    // Do not reinterpret malformed dotted-decimal input as a hostname.
    if host.contains('.') && host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    if host.contains(':') || host.contains('/') || host.contains('\\')
        || host.contains('@') || host.contains('#') || host.contains('?') || host.contains('%') {
        return None;
    }
    let host = host.to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    if labels.iter().any(|label| {
        label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
            || !label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }) {
        return None;
    }
    Some(host)
}

fn mask4(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) }
}
fn mask6(prefix: u8) -> u128 {
    if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) }
}

fn default_path() -> Result<PathBuf, ScopeError> {
    if let Some(path) = env::var_os("INFERNEX_SCOPE_FILE") {
        if path.is_empty() {
            return Err(ScopeError::InvalidEntry("INFERNEX_SCOPE_FILE is empty".into()));
        }
        return Ok(PathBuf::from(path));
    }
    #[cfg(windows)]
    {
        env::var_os("APPDATA").map(PathBuf::from)
            .map(|p| p.join("INFERNEX").join("scope.txt"))
            .ok_or_else(|| ScopeError::Io(io::Error::new(io::ErrorKind::NotFound, "APPDATA is not set")))
    }
    #[cfg(not(windows))]
    {
        env::var_os("XDG_CONFIG_HOME").map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")))
            .map(|p| p.join("infernex").join("scope.txt"))
            .ok_or_else(|| ScopeError::Io(io::Error::new(
                io::ErrorKind::NotFound, "XDG_CONFIG_HOME and HOME are not set")))
    }
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| io::Error::new(
        io::ErrorKind::InvalidInput, "scope path has no file name"))?;
    let mut temp = None;
    let mut file = None;
    for _ in 0..100 {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{}.{}.{}.tmp", name.to_string_lossy(),
            std::process::id(), id));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        // Scope inventories contain authorization decisions. Keep the file
        // private to the current user on Unix even when the process umask is
        // permissive; Windows uses the parent directory's inherited ACL.
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&candidate) {
            Ok(opened) => { temp = Some(candidate); file = Some(opened); break; }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let temp = temp.ok_or_else(|| io::Error::new(
        io::ErrorKind::AlreadyExists, "could not allocate a unique temporary file"))?;
    let result = (|| {
        let mut output = file.expect("temporary file is paired with its path");
        output.write_all(bytes)?;
        output.sync_all()?;
        drop(output);

        // On Unix, rename replaces an existing file atomically. On Windows,
        // std::fs::rename does not replace an existing destination, so use a
        // recoverable backup/rename sequence for subsequent updates.
        #[cfg(windows)]
        {
            match fs::rename(&temp, path) {
                Ok(()) => {}
                Err(first_error)
                    if path.exists()
                        && matches!(
                            first_error.kind(),
                            io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
                        ) =>
                {
                    let backup = loop {
                        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
                        let candidate = parent.join(format!(
                            ".{}.{}.{}.bak",
                            name.to_string_lossy(),
                            std::process::id(),
                            id
                        ));
                        if candidate.exists() {
                            continue;
                        }
                        match fs::rename(path, &candidate) {
                            Ok(()) => break candidate,
                            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                            Err(error) => return Err(error),
                        }
                    };

                    if let Err(replace_error) = fs::rename(&temp, path) {
                        if let Err(restore_error) = fs::rename(&backup, path) {
                            return Err(io::Error::new(
                                replace_error.kind(),
                                format!(
                                    "could not install new scope file ({replace_error}); restoring previous file also failed ({restore_error})"
                                ),
                            ));
                        }
                        return Err(replace_error);
                    }
                    let _ = fs::remove_file(backup);
                }
                Err(error) => return Err(error),
            }
        }
        #[cfg(not(windows))]
        fs::rename(&temp, path)?;

        if let Ok(dir) = File::open(parent) { let _ = dir.sync_all(); }
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temp); }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn manager(label: &str) -> (ScopeManager, PathBuf) {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = env::temp_dir().join(format!("infernex-scope-{label}-{}-{nonce}",
            std::process::id())).join("scope.txt");
        (ScopeManager::with_path(path.clone()), path)
    }
    fn cleanup(path: &Path) {
        if let Some(parent) = path.parent() { let _ = fs::remove_dir_all(parent); }
    }

    #[test]
    fn validates_ipv4_ipv6_and_canonical_cidrs() {
        assert!(matches!(parse_entry("192.0.2.1").unwrap(), ScopeEntry::Ip(IpAddr::V4(_))));
        assert!(matches!(parse_entry("2001:db8::1").unwrap(), ScopeEntry::Ip(IpAddr::V6(_))));
        assert!(parse_entry("999.0.2.1").is_err());
        assert!(parse_entry("2001:db8:::1").is_err());
        assert_eq!(parse_entry("192.0.2.99/24").unwrap().to_string(), "192.0.2.0/24");
        assert_eq!(parse_entry("2001:db8:1::abcd/32").unwrap().to_string(), "2001:db8::/32");
        assert_eq!(parse_entry("192.0.2.7/32").unwrap().to_string(), "192.0.2.7");
        assert_eq!(parse_entry("2001:db8::7/128").unwrap().to_string(), "2001:db8::7");
        for bad in ["192.0.2.1/33", "2001:db8::1/129", "192.0.2.1/-1", "192.0.2.1/24/2"] {
            assert!(parse_entry(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn cidr_boundaries_and_families_are_exact() {
        let v4 = match parse_entry("192.0.2.128/25").unwrap() {
            ScopeEntry::Network(n) => n, _ => unreachable!(),
        };
        assert!(v4.contains("192.0.2.128".parse().unwrap()));
        assert!(v4.contains("192.0.2.255".parse().unwrap()));
        assert!(!v4.contains("192.0.2.127".parse().unwrap()));
        let v6 = match parse_entry("2001:db8:abcd:8000::1/49").unwrap() {
            ScopeEntry::Network(n) => n, _ => unreachable!(),
        };
        assert!(v6.contains("2001:db8:abcd:8000::ffff".parse().unwrap()));
        assert!(!v6.contains("2001:db8:abcd:7fff::1".parse().unwrap()));
        assert!(!v6.contains("192.0.2.1".parse().unwrap()));
        let zero = match parse_entry("0.0.0.0/0").unwrap() {
            ScopeEntry::Network(n) => n, _ => unreachable!(),
        };
        assert!(zero.contains("203.0.113.99".parse().unwrap()));
        assert!(!zero.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn normalizes_and_rejects_hostnames() {
        assert_eq!(parse_entry("LaB.Example.").unwrap().to_string(), "lab.example");
        assert_eq!(parse_entry("LOCALHOST").unwrap().to_string(), "localhost");
        for bad in ["", "*.example.com", "foo?.example", "-bad.example", "bad-.example",
            "a..b", ".example", "example..", "a_b.example", "https://example.com",
            "example.com:443", "user@example.com", "a/b", "bad name", "éxample.com"] {
            assert!(parse_entry(bad).is_err(), "accepted {bad:?}");
        }
        assert!(parse_entry(&format!("{}.example", "a".repeat(64))).is_err());
        assert!(parse_entry(&"a".repeat(254)).is_err());
    }

    #[test]
    fn duplicate_add_remove_and_persistence() {
        let (store, path) = manager("persist");
        store.add("LAB.Example.").unwrap();
        assert!(matches!(store.add("lab.example"), Err(ScopeError::DuplicateEntry(_))));
        store.add("192.0.2.12/24").unwrap();
        assert!(matches!(store.add("192.0.2.0/24"), Err(ScopeError::DuplicateEntry(_))));
        store.add("198.51.100.7/32").unwrap();
        assert!(matches!(store.add("198.51.100.7"), Err(ScopeError::DuplicateEntry(_))));
        let entries = store.list().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(ScopeManager::with_path(&path).list().unwrap(), entries);
        store.remove("LAB.EXAMPLE").unwrap();
        assert_eq!(store.list().unwrap().len(), 2);
        assert!(matches!(store.remove("lab.example"), Err(ScopeError::EntryNotFound(_))));
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn persisted_scope_file_is_private_to_current_user() {
        use std::os::unix::fs::PermissionsExt;

        let (store, path) = manager("private-mode");
        store.add("192.0.2.1").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        cleanup(&path);
    }

    #[test]
    fn missing_storage_is_empty_and_denies() {
        let (store, path) = manager("missing");
        assert!(store.list().unwrap().is_empty());
        assert!(!store.check("192.0.2.1").unwrap());
        cleanup(&path);
    }

    #[test]
    fn corrupt_storage_fails_closed_and_is_not_overwritten() {
        let (store, path) = manager("corrupt");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = "# INFERNEX authorized scope v1\n192.0.2.0/24\n*.example.com\n";
        fs::write(&path, original).unwrap();
        assert!(matches!(store.list(), Err(ScopeError::CorruptStorage { line: 3, .. })));
        assert!(store.check("192.0.2.1").is_err());
        assert!(store.add("lab.example").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        cleanup(&path);
    }

    #[test]
    fn duplicate_records_and_unknown_storage_versions_fail_closed() {
        let (store, path) = manager("storage-integrity");
        fs::create_dir_all(path.parent().unwrap()).unwrap();

        let duplicate = "# INFERNEX authorized scope v1\nLab.Example\nlab.example.\n";
        fs::write(&path, duplicate).unwrap();
        assert!(matches!(
            store.list(),
            Err(ScopeError::CorruptStorage { line: 3, .. })
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), duplicate);

        let unknown_version = "# INFERNEX authorized scope v2\n192.0.2.1\n";
        fs::write(&path, unknown_version).unwrap();
        assert!(matches!(
            store.list(),
            Err(ScopeError::CorruptStorage { line: 1, .. })
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), unknown_version);
        cleanup(&path);
    }

    #[test]
    fn ip_targets_match_exact_ip_or_containing_cidr() {
        let (store, path) = manager("ip-check");
        store.add("192.0.2.0/24").unwrap();
        store.add("2001:db8::/32").unwrap();
        store.add("198.51.100.7").unwrap();
        assert!(store.check("192.0.2.15").unwrap());
        assert!(!store.check("192.0.3.15").unwrap());
        assert!(store.check("2001:db8:1::1").unwrap());
        assert!(!store.check("2001:db9::1").unwrap());
        assert!(store.check("198.51.100.7").unwrap());
        assert!(!store.check("198.51.100.8").unwrap());
        cleanup(&path);
    }

    #[test]
    fn hostname_matching_is_exact_without_dns_or_partial_matches() {
        let (store, path) = manager("host-check");
        store.add("Lab.Example.").unwrap();
        assert!(store.check("lab.example").unwrap());
        assert!(store.check("LAB.EXAMPLE.").unwrap());
        assert!(!store.check("sub.lab.example").unwrap());
        assert!(!store.check("notlab.example").unwrap());
        assert!(!store.check("lab.example.attacker.test").unwrap());
        assert!(store.check("https://lab.example").is_err());
        assert!(store.check("192.0.2.1/24").is_err());
        cleanup(&path);
    }
}
