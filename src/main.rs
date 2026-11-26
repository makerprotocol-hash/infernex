use std::env;
use std::fs::{self, File};
use std::io::Read;
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::net::ToSocketAddrs;
use std::collections::BTreeSet;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy)]
struct Engine { name: &'static str, executable: &'static str, description: &'static str }
const ENGINES: &[Engine] = &[
    Engine { name: "nmap", executable: "nmap", description: "Network discovery and port scanning" },
    Engine { name: "metasploit", executable: "msfconsole", description: "Metasploit Framework console" },
    Engine { name: "tshark", executable: "tshark", description: "Command-line packet analysis" },
    Engine { name: "wireshark", executable: "wireshark", description: "Wireshark graphical application" },
    Engine { name: "sqlmap", executable: "sqlmap", description: "SQL injection testing in authorized labs" },
    Engine { name: "john", executable: "john", description: "Password hash auditing" },
    Engine { name: "hydra", executable: "hydra", description: "Login security auditing" },
];

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() { return repl(); }
    dispatch(&args)
}
fn dispatch(args: &[String]) -> ExitCode {
    match args[0].as_str() {
        "help" | "--help" | "-h" => { banner(); help(); ExitCode::SUCCESS }
        "version" | "--version" | "-V" => { println!("INFERNEX (nex) {VERSION}"); ExitCode::SUCCESS }
        "doctor" => doctor(),
        "hash" => hash_command(&args[1..]),
        "net" => net_command(&args[1..]),
        "theme" => theme_command(&args[1..]),
        "engines" => engines_command(&args[1..]),
        "install" => install_command(&args[1..]),
        "update" => { println!("Self-update is not available yet; use official INFERNEX releases when published."); ExitCode::SUCCESS }
        "exit" | "quit" => ExitCode::SUCCESS,
        name => run_engine(name, &args[1..]),
    }
}
fn repl() -> ExitCode {
    banner();
    println!("Type 'help' for commands, 'exit' to leave.");
    let stdin = io::stdin();
    loop {
        print!("{}nex> \x1b[0m", prompt_color());
        if io::stdout().flush().is_err() { return ExitCode::FAILURE; }
        let mut line = String::new();
        match stdin.read_line(&mut line) {
            Ok(0) => return ExitCode::SUCCESS,
            Ok(_) => {},
            Err(e) => { eprintln!("Input error: {e}"); return ExitCode::FAILURE; }
        }
        let line = line.trim();
        if line.is_empty() { continue; }
        let words = match tokenize(line) { Ok(w) => w, Err(e) => { eprintln!("Command syntax error: {e}"); continue; } };
        if words.is_empty() { continue; }
        if matches!(words[0].as_str(), "exit" | "quit") { break; }
        let status = dispatch(&words);
        if !status.success() { println!("Command finished with status: {}", status.code().unwrap_or(1)); }
    }
    ExitCode::SUCCESS
}
// Quote-aware tokenizer; child arguments are passed directly without shell evaluation.
fn tokenize(input: &str) -> Result<Vec<String>, &'static str> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == q { quote = None; }
            else if c == '\\' && q == '"' {
                match chars.peek().copied() {
                    Some('"') | Some('\\') => current.push(chars.next().unwrap()),
                    _ => current.push(c),
                }
            } else { current.push(c); }
            started = true;
        } else if c == '"' || c == '\'' {
            quote = Some(c);
            started = true;
        } else if c == '\\' {
            match chars.peek().copied() {
                Some(next) if next.is_whitespace() || next == '"' || next == '\'' || next == '\\' => {
                    current.push(chars.next().unwrap());
                }
                _ => current.push(c),
            }
            started = true;
        } else if c.is_whitespace() {
            if started { out.push(std::mem::take(&mut current)); started = false; }
        } else {
            current.push(c);
            started = true;
        }
    }
    if quote.is_some() { return Err("unclosed quote"); }
    if started { out.push(current); }
    Ok(out)
}
fn banner() {
    println!("\x1b[38;5;208m  INFERNEX / NEX\x1b[0m");
    println!("\x1b[38;5;202m  Unified cybersecurity command environment\x1b[0m");
    println!("Version {VERSION}\n");
}
fn help() {
    println!("Usage: nex <command> [arguments]");
    println!("  help                         Show help");
    println!("  version                      Show version");
    println!("  doctor                       Check basic environment");
    println!("  net resolve <hostname>        Resolve a hostname using system DNS");
    println!("  hash sha256 <file>            Calculate a file SHA-256 digest");
    println!("  hash verify sha256 <file> <expected>  Verify a file digest");
    println!("  engines [check]              List/check supported integrations");
    println!("  install <engine>             Show installation guidance");
    println!("  theme list|set <name>        Manage terminal theme");
    println!("  <engine> [original args...]  Run an integrated engine");
    println!("\nExamples:\n  nex nmap -sV 192.0.2.10\n  nex metasploit\n  nex theme set ember");
    println!("\nOnly assess systems and networks you own or are explicitly authorized to test.");
}
fn net_command(args: &[String]) -> ExitCode {
    match args {
        [action, hostname] if action == "resolve" => {
            if hostname.is_empty() || hostname.contains('/') || hostname.contains('\\') {
                eprintln!("Provide a hostname, not a URL or path.");
                return ExitCode::from(2);
            }
            match (hostname.as_str(), 0).to_socket_addrs() {
                Ok(addresses) => {
                    let ips: BTreeSet<String> = addresses.map(|a| a.ip().to_string()).collect();
                    if ips.is_empty() {
                        println!("No addresses returned for {hostname}.");
                        return ExitCode::from(1);
                    }
                    println!("DNS results for {hostname}:");
                    for ip in ips { println!("  {ip}"); }
                    ExitCode::SUCCESS
                }
                Err(e) => { eprintln!("DNS resolution failed for {hostname}: {e}"); ExitCode::from(1) }
            }
        }
        _ => { eprintln!("Usage: nex net resolve <hostname>"); ExitCode::from(2) }
    }
}

fn hash_command(args: &[String]) -> ExitCode {
    match args {
        [algorithm, path] if algorithm == "sha256" => match sha256_file(path) {
            Ok(digest) => { println!("{}  {}", digest, path); ExitCode::SUCCESS },
            Err(e) => { eprintln!("Cannot hash '{}': {}", path, e); ExitCode::FAILURE }
        },
        [action, algorithm, path, expected] if action == "verify" && algorithm == "sha256" => {
            if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
                eprintln!("Expected SHA-256 must be exactly 64 hexadecimal characters.");
                return ExitCode::from(2);
            }
            match sha256_file(path) {
                Ok(actual) if actual.eq_ignore_ascii_case(expected) => { println!("OK: SHA-256 matches for '{}'.", path); ExitCode::SUCCESS },
                Ok(actual) => { eprintln!("MISMATCH: expected {}, got {}", expected, actual); ExitCode::from(1) },
                Err(e) => { eprintln!("Cannot hash '{}': {}", path, e); ExitCode::FAILURE }
            }
        }
        _ => { eprintln!("Usage: nex hash sha256 <file> | nex hash verify sha256 <file> <expected-hex>"); ExitCode::from(2) }
    }
}
fn sha256_file(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
fn doctor() -> ExitCode {
    println!("INFERNEX diagnostics\nCore: {VERSION}\nOS: {}\nArchitecture: {}", env::consts::OS, env::consts::ARCH);
    println!("Config: {}", config_path().map(|p| p.display().to_string()).unwrap_or_else(|| "unavailable".into()));
    println!("Run 'nex engines check' to inspect optional integrations.");
    ExitCode::SUCCESS
}
fn engines_command(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        None => { println!("Supported integrations (not bundled):"); for e in ENGINES { println!("  {:12} [{}] {}", e.name, e.executable, e.description); } ExitCode::SUCCESS }
        Some("check") => {
            let mut missing = 0;
            for e in ENGINES {
                let found = executable_available(e.executable);
                println!("{} {:12} {}", if found { "[FOUND]" } else { "[MISSING]" }, e.name, e.executable);
                if !found { missing += 1; }
            }
            println!("\n{} available, {} missing.", ENGINES.len() - missing, missing);
            ExitCode::SUCCESS
        }
        _ => { eprintln!("Usage: nex engines [check]"); ExitCode::from(2) }
    }
}
fn executable_available(exe: &str) -> bool {
    let path = match env::var_os("PATH") { Some(p) => p, None => return false };
    for dir in env::split_paths(&path) {
        #[cfg(windows)]
        let candidates = vec![dir.join(format!("{exe}.exe")), dir.join(format!("{exe}.cmd")), dir.join(exe)];
        #[cfg(not(windows))]
        let candidates = vec![dir.join(exe)];
        if candidates.iter().any(|p| p.is_file()) { return true; }
    }
    false
}
fn install_command(args: &[String]) -> ExitCode {
    let Some(name) = args.first() else { eprintln!("Usage: nex install <engine>"); return ExitCode::from(2); };
    let Some(engine) = ENGINES.iter().find(|e| e.name == name) else { eprintln!("Unknown engine '{name}'. Run 'nex engines'."); return ExitCode::from(2); };
    println!("Installation guidance for {} ({})", engine.name, engine.executable);
    println!("Automatic third-party installation is not implemented yet.");
    println!("Use the upstream project's official source and review its license before installing.");
    #[cfg(windows)]
    println!("Windows: follow the upstream project's official Windows installation instructions.");
    #[cfg(target_os = "linux")]
    println!("Linux: use your distribution's trusted package manager where supported.");
    println!("After installation, run 'nex engines check'.");
    ExitCode::SUCCESS
}
fn theme_command(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("list") => { println!("ember\nspectrum\nmono"); ExitCode::SUCCESS }
        Some("set") if args.len() >= 2 => {
            let theme = args[1].to_lowercase();
            if !["ember", "spectrum", "mono"].contains(&theme.as_str()) { eprintln!("Unknown theme '{theme}'. Run 'nex theme list'."); return ExitCode::from(2); }
            let Some(path) = config_path() else { eprintln!("Cannot determine config directory."); return ExitCode::FAILURE; };
            if let Some(parent) = path.parent() { if let Err(e) = fs::create_dir_all(parent) { eprintln!("Cannot create config directory: {e}"); return ExitCode::FAILURE; } }
            if let Err(e) = set_config_value(&path, "theme", &theme) { eprintln!("Cannot save theme: {e}"); return ExitCode::FAILURE; }
            println!("Theme saved: {theme}"); ExitCode::SUCCESS
        }
        _ => { eprintln!("Usage: nex theme <list|set <name>>"); ExitCode::from(2) }
    }
}
fn set_config_value(path: &std::path::Path, key: &str, value: &str) -> io::Result<()> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    let mut lines = Vec::new();
    let mut replaced = false;
    for line in existing.lines() {
        if line.split_once('=').map(|(k, _)| k.trim() == key).unwrap_or(false) {
            if !replaced { lines.push(format!("{key}={value}")); replaced = true; }
        } else { lines.push(line.to_string()); }
    }
    if !replaced { lines.push(format!("{key}={value}")); }
    fs::write(path, format!("{}\n", lines.join("\n")))
}
fn prompt_color() -> &'static str {
    let theme = config_path()
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|contents| contents.lines().find_map(|line| line.strip_prefix("theme=")).map(str::trim).map(str::to_owned));
    match theme.as_deref() {
        Some("spectrum") => "\x1b[38;5;45m",
        Some("mono") => "\x1b[38;5;250m",
        _ => "\x1b[38;5;208m",
    }
}

fn config_path() -> Option<PathBuf> {
    #[cfg(windows)]
    { env::var_os("APPDATA").map(|p| PathBuf::from(p).join("INFERNEX").join("config.ini")) }
    #[cfg(not(windows))]
    { env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).or_else(|| env::var_os("HOME").map(|p| PathBuf::from(p).join(".config"))).map(|p| p.join("infernex").join("config.ini")) }
}
fn run_engine(name: &str, args: &[String]) -> ExitCode {
    let Some(engine) = ENGINES.iter().find(|e| e.name == name) else { eprintln!("Unknown command or engine '{name}'. Run 'nex help' or 'nex engines'."); return ExitCode::from(2); };
    match Command::new(engine.executable).args(args).status() {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1).clamp(0, 255) as u8),
        Err(e) if e.kind() == io::ErrorKind::NotFound => { eprintln!("Engine '{}' is not installed or not on PATH. Run 'nex install {}'.", engine.name, engine.name); ExitCode::from(127) }
        Err(e) => { eprintln!("Could not start {}: {e}", engine.name); ExitCode::FAILURE }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn tokenizes_plain_args() { assert_eq!(tokenize("nmap -sV host").unwrap(), vec!["nmap", "-sV", "host"]); }
    #[test] fn tokenizes_quoted_args() { assert_eq!(tokenize("web --url \"https://example.test/a b\"").unwrap(), vec!["web", "--url", "https://example.test/a b"]); }
    #[test] fn rejects_unclosed_quote() { assert!(tokenize("nmap \"host").is_err()); }
    #[test] fn preserves_windows_path_backslashes() { assert_eq!(tokenize(r#"hash sha256 C:\Users\Public\file.bin"#).unwrap(), vec!["hash", "sha256", r#"C:\Users\Public\file.bin"#]); }
    #[test] fn metasploit_alias_maps_to_console() { assert!(ENGINES.iter().any(|e| e.name == "metasploit" && e.executable == "msfconsole")); }
    #[test] fn sha256_known_vector() { let digest = Sha256::digest(b"abc"); assert_eq!(format!("{:x}", digest), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"); }
    #[test] fn hashes_file_contents() {
        let path = env::temp_dir().join(format!("infernex-hash-test-{}", std::process::id()));
        fs::write(&path, b"abc").unwrap();
        assert_eq!(sha256_file(path.to_str().unwrap()).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        fs::remove_file(path).unwrap();
    }
}
