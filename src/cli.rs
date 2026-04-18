//! CLI parsing and execution.

use std::path::PathBuf;

use clap::Parser;

/// Sandbox Runtime - OS-level sandboxing tool
#[derive(Parser, Debug)]
#[command(name = "srt")]
#[command(about = "Sandbox Runtime - enforce filesystem and network restrictions on processes")]
#[command(version)]
pub struct Cli {
    /// Enable debug logging
    #[arg(short = 'd', long = "debug")]
    pub debug: bool,

    /// Path to settings file (default: ~/.srt-settings.json)
    #[arg(short = 's', long = "settings")]
    pub settings: Option<PathBuf>,

    /// Run command string directly (sh -c mode)
    #[arg(short = 'c')]
    pub command: Option<String>,

    /// Read config updates from file descriptor (JSON lines protocol)
    #[arg(long = "control-fd")]
    pub control_fd: Option<i32>,

    /// Command and arguments to run
    #[arg(trailing_var_arg = true)]
    pub args: Vec<String>,
}

impl Cli {
    /// Parse CLI arguments.
    pub fn parse_args() -> Self {
        Cli::parse()
    }

    /// Get the command to execute.
    /// Returns (command_string, shell_mode)
    /// - shell_mode = true when using -c flag
    /// - shell_mode = false when using positional args
    pub fn get_command(&self) -> Option<(String, bool)> {
        if let Some(ref cmd) = self.command {
            Some((cmd.clone(), true))
        } else if !self.args.is_empty() {
            // Join args with proper quoting
            let cmd = crate::utils::join_args(&self.args);
            Some((cmd, false))
        } else {
            None
        }
    }

    /// Get the settings file path.
    pub fn get_settings_path(&self) -> Option<PathBuf> {
        self.settings.clone().or_else(crate::config::default_settings_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_flag_executes_simple_command_contract() {
        let cli = Cli::parse_from(["srt", "-c", "echo hello"]);
        let (command, shell_mode) = cli.get_command().expect("command should exist");
        assert_eq!(command, "echo hello");
        assert!(shell_mode);
    }

    #[test]
    fn test_c_flag_passes_command_string_directly_without_escaping() {
        let cli = Cli::parse_from(["srt", "-c", r#"echo "hello world""#]);
        let (command, shell_mode) = cli.get_command().expect("command should exist");
        assert_eq!(command, r#"echo "hello world""#);
        assert!(shell_mode);
    }

    #[test]
    fn test_c_flag_handles_json_arguments_correctly() {
        let cli = Cli::parse_from(["srt", "-c", r#"echo '{"key": "value"}'"#]);
        let (command, shell_mode) = cli.get_command().expect("command should exist");
        assert_eq!(command, r#"echo '{"key": "value"}'"#);
        assert!(shell_mode);
    }

    #[test]
    fn test_c_flag_handles_complex_json_with_nested_objects() {
        let json = r#"{"servers":{"name":"test","type":"sdk"}}"#;
        let cli = Cli::parse_from(["srt", "-c", &format!("echo '{json}'")]);
        let (command, shell_mode) = cli.get_command().expect("command should exist");
        assert_eq!(command, format!("echo '{json}'"));
        assert!(shell_mode);
    }

    #[test]
    fn test_default_mode_executes_simple_command_contract() {
        let cli = Cli::parse_from(["srt", "echo", "hello"]);
        let (command, shell_mode) = cli.get_command().expect("command should exist");
        assert_eq!(command, "echo hello");
        assert!(!shell_mode);
    }

    #[test]
    fn test_default_mode_joins_multiple_positional_arguments_with_spaces() {
        let cli = Cli::parse_from(["srt", "echo", "hello", "world"]);
        let (command, shell_mode) = cli.get_command().expect("command should exist");
        assert_eq!(command, "echo hello world");
        assert!(!shell_mode);
    }

    #[test]
    fn test_default_mode_handles_arguments_with_flags() {
        let cli = Cli::parse_from(["srt", "echo", "-n", "no newline"]);
        let (command, shell_mode) = cli.get_command().expect("command should exist");
        assert_eq!(command, "echo -n 'no newline'");
        assert!(!shell_mode);
    }

    #[test]
    fn test_no_command_specified_returns_none() {
        let cli = Cli::parse_from(["srt"]);
        assert!(cli.get_command().is_none());
    }

    #[test]
    fn test_only_options_without_command_returns_none() {
        let cli = Cli::parse_from(["srt", "-d"]);
        assert!(cli.get_command().is_none());
    }
}
