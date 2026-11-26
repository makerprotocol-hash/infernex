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
struct Engine { name: &'static str, executable: &'static str, description: &'static str, upstream: &'static str }
const ENGINES: &[Engine] = &[
    Engine { name: "nmap", executable: "nmap", description: "Network discovery and port scanning", upstream: "https://nmap.org/download.html" },
    Engine { name: "metasploit", executable: "msfconsole", description: "Metasploit Framework console", upstream: "https://docs.metasploit.com/" },
    Engine { name: "tshark", executable: "tshark", description: "Command-line packet analysis", upstream: "https://www.wireshark.org/download.html" },
    Engine { name: "wireshark", executable: "wireshark", description: "Wireshark graphical application", upstream: "https://www.wireshark.org/download.html" },
    Engine { name: "sqlmap", executable: "sqlmap", description: "SQL injection testing in authorized labs", upstream: "https://github.com/sqlmapproject/sqlmap" },
    Engine { name: "john", executable: "john", description: "Password hash auditing", upstream: "https://www.openwall.com/john/" },
    Engine { name: "hydra", executable: "hydra", description: "Login security auditing", upstream: "https://github.com/vanhauser-thc/thc-hydra" },
];

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() { return repl(); }
    dispatch(&args)
}
fn dispatch(args: &[String]) -> ExitCode {
    dispatch_with_aliases(args, 0)
}
fn dispatch_with_aliases(args: &[String], depth: usize) -> ExitCode {
    if depth >= 8 { eprintln!("Alias expansion limit reached."); return ExitCode::from(2); }
    if !is_builtin_command(&args[0]) {
        if let Some(value) = alias_value(&args[0]) {
            match tokenize(&value) {
                Ok(mut expanded) if !expanded.is_empty() => {
                    expanded.extend_from_slice(&args[1..]);
                    return dispatch_with_aliases(&expanded, depth + 1);
                }
                _ => { eprintln!("Configured alias '{}' is invalid.", args[0]); return ExitCode::from(2); }
            }
        }
    }
    match args[0].as_str() {
        "help" | "--help" | "-h" => { banner(); help(); ExitCode::SUCCESS }
        "version" | "--version" | "-V" => { println!("INFERNEX (nex) {VERSION}"); ExitCode::SUCCESS }
        "doctor" => doctor(),
        "hash" => hash_command(&args[1..]),
        "net" => net_command(&args[1..]),
        "theme" => theme_command(&args[1..]),
        "alias" => alias_command(&args[1..]),
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
        print!("{}nex>{}", prompt_color(), prompt_reset());
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
    if colors_enabled() {
        println!("\x1b[38;5;208m  INFERNEX / NEX\x1b[0m");
        println!("\x1b[38;5;202m  Unified cybersecurity command environment\x1b[0m");
    } else {
        println!("  INFERNEX / NEX");
        println!("  Unified cybersecurity command environment");
    }
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
    println!("  engines [check|info <name>]  List/check/inspect integrations");
    println!("  install <engine>             Install Nmap (Linux) or show guidance");
    println!("  theme list|set <name>        Manage terminal theme");
    println!("  alias list|add|remove         Manage safe command aliases");
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
        Some("info") if args.len() == 2 => {
            let Some(engine) = ENGINES.iter().find(|e| e.name == args[1]) else {
                eprintln!("Unknown engine '{}'. Run 'nex engines'.", args[1]);
                return ExitCode::from(2);
            };
            println!("{} — {}", engine.name, engine.description);
            println!("Executable: {}", engine.executable);
            println!("Status: {}", if executable_available(engine.executable) { "available on PATH" } else { "not found on PATH" });
            println!("Official upstream: {}", engine.upstream);
            if engine.name == "nmap" {
                println!("Install: nex install nmap");
            } else {
                println!("Install guidance: nex install {}", engine.name);
            }
            ExitCode::SUCCESS
        }
        _ => { eprintln!("Usage: nex engines [check | info <engine>]"); ExitCode::from(2) }
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
    if args.len() != 1 {
        eprintln!("Usage: nex install <engine>");
        return ExitCode::from(2);
    }
    let name = args[0].as_str();
    let Some(engine) = ENGINES.iter().find(|e| e.name == name) else {
        eprintln!("Unknown engine '{name}'. Run 'nex engines'.");
        return ExitCode::from(2);
    };
    if executable_available(engine.executable) {
        println!("{} is already available on PATH.", engine.name);
        return ExitCode::SUCCESS;
    }
    if engine.name == "nmap" {
        return install_nmap();
    }
    println!("Installation guidance for {} ({})", engine.name, engine.executable);
    println!("Official upstream: {}", engine.upstream);
    println!("INFERNEX does not yet automate installation of this engine.");
    println!("Use the upstream project's official source and review its license before installing.");
    println!("After installation, run 'nex engines check'.");
    ExitCode::SUCCESS
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinuxPackageManager { Apt, Dnf, Yum, Pacman, Zypper }

fn detect_linux_package_manager() -> Option<LinuxPackageManager> {
    if executable_available("apt-get") { Some(LinuxPackageManager::Apt) }
    else if executable_available("dnf") { Some(LinuxPackageManager::Dnf) }
    else if executable_available("yum") { Some(LinuxPackageManager::Yum) }
    else if executable_available("pacman") { Some(LinuxPackageManager::Pacman) }
    else if executable_available("zypper") { Some(LinuxPackageManager::Zypper) }
    else { None }
}

fn linux_nmap_install_command(manager: LinuxPackageManager) -> (&'static str, &'static [&'static str]) {
    match manager {
        LinuxPackageManager::Apt => ("sudo", &["apt-get", "install", "-y", "nmap"]),
        LinuxPackageManager::Dnf => ("sudo", &["dnf", "install", "-y", "nmap"]),
        LinuxPackageManager::Yum => ("sudo", &["yum", "install", "-y", "nmap"]),
        LinuxPackageManager::Pacman => ("sudo", &["pacman", "-S", "--needed", "--noconfirm", "nmap"]),
        LinuxPackageManager::Zypper => ("sudo", &["zypper", "--non-interactive", "install", "nmap"]),
    }
}

fn install_nmap() -> ExitCode {
    #[cfg(windows)]
    {
        println!("Automatic Nmap installation is not enabled on Windows yet.");
        println!("Download the official Nmap installer from https://nmap.org/download.html");
        println!("Review the installer options, including Npcap, before proceeding.");
        return ExitCode::SUCCESS;
    }
    #[cfg(target_os = "linux")]
    {
        let Some(manager) = detect_linux_package_manager() else {
            eprintln!("No supported package manager found (apt-get, dnf, yum, pacman, zypper).");
            eprintln!("Install Nmap from https://nmap.org/download.html");
            return ExitCode::from(1);
        };
        let (program, args) = linux_nmap_install_command(manager);
        println!("INFERNEX is ready to request Nmap installation using {program} {}.", args.join(" "));
        println!("This will modify your system and may install additional dependencies.");
        println!("Only continue if you trust your configured package repositories.");
        print!("Type YES to authorize this package-manager operation: ");
        if io::stdout().flush().is_err() { return ExitCode::FAILURE; }
        let mut confirmation = String::new();
        if io::stdin().read_line(&mut confirmation).is_err() { return ExitCode::FAILURE; }
        if confirmation.trim() != "YES" {
            println!("Installation cancelled. No package manager was started.");
            return ExitCode::SUCCESS;
        }
        match Command::new(program).args(args).status() {
            Ok(status) if status.success() => {
                if executable_available("nmap") {
                    println!("Nmap installation completed and nmap is available on PATH.");
                    ExitCode::SUCCESS
                } else {
                    println!("Package manager completed. Open a new terminal or check PATH with 'nex engines check'.");
                    ExitCode::from(1)
                }
            }
            Ok(status) => {
                eprintln!("Package manager exited with status {}.", status.code().unwrap_or(1));
                ExitCode::from(status.code().unwrap_or(1).clamp(1, 255) as u8)
            }
            Err(error) => { eprintln!("Could not start package manager: {error}"); ExitCode::FAILURE }
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        println!("Automatic Nmap installation is supported only on Windows/Linux guidance and Linux package managers.");
        println!("Official upstream: https://nmap.org/download.html");
        ExitCode::SUCCESS
    }
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
fn alias_command(args: &[String]) -> ExitCode {
    match args {
        [action] if action == "list" => {
            let Some(path) = config_path() else { eprintln!("Cannot determine config directory."); return ExitCode::FAILURE; };
            let config = fs::read_to_string(path).unwrap_or_default();
            let mut found = false;
            for line in config.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    if let Some(name) = key.strip_prefix("alias.") { println!("{name} = {value}"); found = true; }
                }
            }
            if !found { println!("No aliases configured."); }
            ExitCode::SUCCESS
        }
        [action, name] if action == "remove" => {
            if !valid_alias_name(name) { eprintln!("Invalid alias name."); return ExitCode::from(2); }
            let Some(path) = config_path() else { eprintln!("Cannot determine config directory."); return ExitCode::FAILURE; };
            if let Err(e) = remove_config_value(&path, &format!("alias.{name}")) { eprintln!("Cannot update config: {e}"); return ExitCode::FAILURE; }
            println!("Alias removed: {name}");
            ExitCode::SUCCESS
        }
        [action, name, command @ ..] if action == "add" && !command.is_empty() => {
            if !valid_alias_name(name) || is_builtin_command(name) { eprintln!("Invalid or reserved alias name."); return ExitCode::from(2); }
            let value = command.iter().map(|part| quote_token(part)).collect::<Vec<_>>().join(" ");
            if tokenize(&value).map(|v| v.is_empty()).unwrap_or(true) { eprintln!("Alias command is invalid."); return ExitCode::from(2); }
            let Some(path) = config_path() else { eprintln!("Cannot determine config directory."); return ExitCode::FAILURE; };
            if let Some(parent) = path.parent() { if let Err(e) = fs::create_dir_all(parent) { eprintln!("Cannot create config directory: {e}"); return ExitCode::FAILURE; } }
            if let Err(e) = set_config_value(&path, &format!("alias.{name}"), &value) { eprintln!("Cannot save alias: {e}"); return ExitCode::FAILURE; }
            println!("Alias saved: {name} = {value}");
            ExitCode::SUCCESS
        }
        _ => { eprintln!("Usage: nex alias list | nex alias add <name> <command> [args...] | nex alias remove <name>"); ExitCode::from(2) }
    }
}
fn alias_value(name: &str) -> Option<String> {
    let path = config_path()?;
    let config = fs::read_to_string(path).ok()?;
    config.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        if key.trim() == format!("alias.{name}") { Some(value.to_string()) } else { None }
    })
}
fn valid_alias_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 32 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}
fn is_builtin_command(name: &str) -> bool {
    matches!(name, "help" | "version" | "doctor" | "hash" | "net" | "theme" | "engines" | "install" | "update" | "alias" | "exit" | "quit") || ENGINES.iter().any(|engine| engine.name == name)
}
fn remove_config_value(path: &std::path::Path, key: &str) -> io::Result<()> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = existing.lines().filter(|line| line.split_once('=').map(|(k, _)| k.trim() != key).unwrap_or(true)).collect();
    fs::write(path, if lines.is_empty() { String::new() } else { format!("{}\n", lines.join("\n")) })
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
fn colors_enabled() -> bool {
    env::var_os("NO_COLOR").map(|value| !value.is_empty()).unwrap_or(true)
}

fn prompt_color() -> &'static str {
    if !colors_enabled() { return ""; }
    let theme = config_path()
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|contents| contents.lines().find_map(|line| line.strip_prefix("theme=")).map(str::trim).map(str::to_owned));
    match theme.as_deref() {
        Some("spectrum") => "\x1b[38;5;45m",
        Some("mono") => "\x1b[38;5;250m",
        _ => "\x1b[38;5;208m",
    }
}

fn prompt_reset() -> &'static str {
    if colors_enabled() { "\x1b[0m" } else { "" }
}

// Encode one argument so the REPL tokenizer reconstructs it exactly.
fn quote_token(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
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
    #[test] fn alias_argument_encoding_round_trips_spaces_and_windows_paths() {
        let original = vec!["nmap".to_string(), "-oN".to_string(), "report file.txt".to_string(), r#"C:\Users\Public\scan output.txt"#.to_string(), r#"say \"hello\""#.to_string()];
        let encoded = original.iter().map(|part| quote_token(part)).collect::<Vec<_>>().join(" ");
        assert_eq!(tokenize(&encoded).unwrap(), original);
    }
    #[test] fn preserves_windows_path_backslashes() { assert_eq!(tokenize(r#"hash sha256 C:\Users\Public\file.bin"#).unwrap(), vec!["hash", "sha256", r#"C:\Users\Public\file.bin"#]); }
    #[test] fn metasploit_alias_maps_to_console() { assert!(ENGINES.iter().any(|e| e.name == "metasploit" && e.executable == "msfconsole")); }
    #[test] fn linux_package_manager_commands_are_explicit_and_target_nmap() {
        assert_eq!(linux_nmap_install_command(LinuxPackageManager::Apt), ("sudo", &["apt-get", "install", "-y", "nmap"][..]));
        assert_eq!(linux_nmap_install_command(LinuxPackageManager::Dnf), ("sudo", &["dnf", "install", "-y", "nmap"][..]));
        assert_eq!(linux_nmap_install_command(LinuxPackageManager::Yum), ("sudo", &["yum", "install", "-y", "nmap"][..]));
        assert_eq!(linux_nmap_install_command(LinuxPackageManager::Pacman), ("sudo", &["pacman", "-S", "--needed", "--noconfirm", "nmap"][..]));
        assert_eq!(linux_nmap_install_command(LinuxPackageManager::Zypper), ("sudo", &["zypper", "--non-interactive", "install", "nmap"][..]));
    }
    #[test] fn sha256_known_vector() { let digest = Sha256::digest(b"abc"); assert_eq!(format!("{:x}", digest), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"); }
    #[test] fn config_update_preserves_other_settings() {
        let path = env::temp_dir().join(format!("infernex-config-test-{}", std::process::id()));
        fs::write(&path, "theme=mono\naliases=true\n").unwrap();
        set_config_value(&path, "theme", "ember").unwrap();
        let saved = fs::read_to_string(&path).unwrap();
        assert!(saved.contains("theme=ember"));
        assert!(saved.contains("aliases=true"));
        fs::remove_file(path).unwrap();
    }
    #[test] fn hashes_file_contents() {
        let path = env::temp_dir().join(format!("infernex-hash-test-{}", std::process::id()));
        fs::write(&path, b"abc").unwrap();
        assert_eq!(sha256_file(path.to_str().unwrap()).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        fs::remove_file(path).unwrap();
    }
}
