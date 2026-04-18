use std::process::Command;

fn run_cli(args: &[&str], debug_env: bool) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_srt");
    let mut cmd = Command::new(bin);
    cmd.args(args);
    cmd.env("HOME", "/tmp/cli-test-nonexistent");
    if debug_env {
        cmd.env("SRT_DEBUG", "true");
    } else {
        cmd.env_remove("SRT_DEBUG");
    }
    cmd.output().expect("cli should execute")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn executes_simple_command_with_c_flag() {
    let output = run_cli(&["-c", "echo hello"], false);
    assert!(output.status.success());
    assert_eq!(stdout(&output).trim(), "hello");
}

#[test]
fn passes_command_string_directly_without_escaping() {
    let output = run_cli(&["-c", r#"echo "hello world""#], false);
    assert!(output.status.success());
    assert_eq!(stdout(&output).trim(), "hello world");
}

#[test]
fn handles_json_arguments_correctly() {
    let output = run_cli(&["-c", r#"echo '{"key": "value"}'"#], false);
    assert!(output.status.success());
    assert_eq!(stdout(&output).trim(), r#"{"key": "value"}"#);
}

#[test]
fn handles_complex_json_with_nested_objects() {
    let json = r#"{"servers":{"name":"test","type":"sdk"}}"#;
    let command = format!("echo '{json}'");
    let output = run_cli(&["-c", &command], false);
    assert!(output.status.success());
    assert_eq!(stdout(&output).trim(), json);
}

#[test]
fn handles_shell_expansion_in_c_mode() {
    let output = run_cli(&["-c", "echo $HOME"], false);
    assert!(output.status.success());
    assert_ne!(stdout(&output).trim(), "$HOME");
}

#[test]
fn handles_pipes_in_c_mode() {
    let output = run_cli(&["-c", r#"echo "hello world" | wc -w"#], false);
    assert!(output.status.success());
    assert_eq!(stdout(&output).trim(), "2");
}

#[test]
fn handles_command_substitution_in_c_mode() {
    let output = run_cli(&["-c", r#"echo "count: $(echo 1 2 3 | wc -w)""#], false);
    assert!(output.status.success());
    assert!(stdout(&output).trim().contains('3'));
}

#[test]
fn executes_simple_command_with_positional_args() {
    let output = run_cli(&["echo", "hello"], false);
    assert!(output.status.success());
    assert_eq!(stdout(&output).trim(), "hello");
}

#[test]
fn joins_multiple_positional_arguments_with_spaces() {
    let output = run_cli(&["echo", "hello", "world"], false);
    assert!(output.status.success());
    assert_eq!(stdout(&output).trim(), "hello world");
}

#[test]
fn handles_arguments_with_flags() {
    let output = run_cli(&["echo", "-n", "no newline"], false);
    assert!(output.status.success());
    assert_eq!(stdout(&output), "no newline");
}

#[test]
fn shows_error_when_no_command_specified() {
    let output = run_cli(&[], false);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("No command specified"));
}

#[test]
fn shows_error_when_only_options_provided_without_command() {
    let output = run_cli(&["-d"], false);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("No command specified"));
}

#[test]
fn srt_debug_enables_debug_output_for_positional_args() {
    let output = run_cli(&["echo", "test"], true);
    assert!(output.status.success());
    assert!(stderr(&output).contains("Original command"));
    assert!(stderr(&output).contains("Wrapped command"));
}

#[test]
fn srt_debug_enables_debug_output_for_c_mode() {
    let output = run_cli(&["-c", "echo test"], true);
    assert!(output.status.success());
    assert!(stderr(&output).contains("Command string mode"));
    assert!(stderr(&output).contains("Wrapped command"));
}

#[test]
fn no_debug_output_without_srt_debug() {
    let output = run_cli(&["echo", "test"], false);
    assert!(output.status.success());
    assert!(!stderr(&output).contains("Original command"));
    assert!(!stderr(&output).contains("Command string mode"));
}
