use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_banner();
        print_help();
        return ExitCode::SUCCESS;
    };
    let rest: Vec<String> = args.collect();

    match command.as_str() {
        "help" | "--help" | "-h" => {
            print_banner();
            print_help();
            ExitCode::SUCCESS
        }
        "version" | "--version" | "-V" => {
            println!("INFERNEX (nex) {VERSION}");
            ExitCode::SUCCESS
        }
        "theme" => theme_command(&rest),
        "doctor" => {
            println!("INFERNEX diagnostics");
            println!("Core: {VERSION}");
            println!("Platform: {}", env::consts::OS);
            println!("Architecture: {}", env::consts::ARCH);
            println!("External engine discovery will be added in a later milestone.");
            ExitCode::SUCCESS
        }
        other => run_engine(other, &rest),
    }
}

fn print_banner() {
    println!("\x1b[38;5;208m  ___ _   _ _____ _____ ____  _   _ _____  X\x1b[0m");
    println!("\x1b[38;5;202m |_ _| \\ | |  ___| ____|  _ \\| \\ | | ____|\x1b[0m");
    println!("\x1b[38;5;196m  | |  \\| | |_  |  _| | |_) |  \\| |  _|\x1b[0m");
    println!("\x1b[38;5;208m  | | |\\  |  _| | |___|  _ <| |\\  | |___\x1b[0m");
    println!("\x1b[38;5;202m |___|_| \\_|_|   |_____|_| \\_\\_| \\_|_____|\x1b[0m");
    println!("INFERNEX {VERSION} — unified security command environment");
    println!();
}

fn print_help() {
    println!("Usage: nex <command> [arguments]");
    println!();
    println!("Core commands:");
    println!("  help                 Show this help");
    println!("  version              Show version");
    println!("  doctor               Show basic environment diagnostics");
    println!("  theme list           List built-in themes");
    println!("  theme set <name>     Save a preferred theme");
    println!();
    println!("Integrated engine commands (engine must be installed separately):");
    println!("  nex nmap [args...]       Run Nmap with unchanged arguments");
    println!("  nex metasploit [args...] Run the Metasploit console");
    println!("  nex tshark [args...]     Run TShark with unchanged arguments");
    println!();
    println!("Examples:");
    println!("  nex nmap -sV 192.0.2.10");
    println!("  nex tshark -i 1");
    println!("  nex theme set ember");
    println!();
    println!("Use only on systems and networks you own or are authorized to test.");
}

fn theme_command(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("list") => {
            println!("Available themes:");
            println!("  ember    Deep orange / crimson");
            println!("  spectrum Colorful module indicators");
            println!("  mono     Minimal monochrome");
            ExitCode::SUCCESS
        }
        Some("set") if args.len() >= 2 => {
            let theme = args[1].to_lowercase();
            if !["ember", "spectrum", "mono"].contains(&theme.as_str()) {
                eprintln!("Unknown theme '{theme}'. Run 'nex theme list'.");
                return ExitCode::from(2);
            }
            match config_path() {
                Some(path) => {
                    if let Some(parent) = path.parent() {
                        if let Err(error) = fs::create_dir_all(parent) {
                            eprintln!("Could not create config directory: {error}");
                            return ExitCode::FAILURE;
                        }
                    }
                    if let Err(error) = fs::write(&path, format!("theme={theme}\n")) {
                        eprintln!("Could not save theme: {error}");
                        return ExitCode::FAILURE;
                    }
                    println!("Theme saved: {theme}");
                    ExitCode::SUCCESS
                }
                None => {
                    eprintln!("Could not determine a user config directory on this system.");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("Usage: nex theme <list|set <name>>");
            ExitCode::from(2)
        }
    }
}

fn config_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        env::var_os("APPDATA").map(|p| PathBuf::from(p).join("INFERNEX").join("config.ini"))
    }
    #[cfg(not(windows))]
    {
        env::var_os("HOME").map(|p| PathBuf::from(p).join(".config").join("infernex").join("config.ini"))
    }
}

fn run_engine(name: &str, args: &[String]) -> ExitCode {
    // Pass arguments directly to the upstream executable. Do not rewrite flags or shell-join
    // user input: Command::args preserves argument boundaries and avoids shell interpolation.
    let executable = match name {
        "metasploit" => "msfconsole",
        other => other,
    };

    let status = Command::new(executable).args(args).status();
    match status {
        Ok(status) => ExitCode::from(status.code().unwrap_or(1).clamp(0, 255) as u8),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("Engine '{name}' was not found.");
            eprintln!("Install the corresponding tool and ensure its executable is on PATH.");
            eprintln!("INFERNEX does not bundle or rebrand third-party engines automatically.");
            ExitCode::from(127)
        }
        Err(error) => {
            eprintln!("Could not start engine '{name}': {error}");
            ExitCode::FAILURE
        }
    }
}
