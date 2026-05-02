//! Bubblewrap command generation for Linux sandbox.

use std::path::Path;

use crate::config::SandboxRuntimeConfig;
use crate::error::SandboxError;
use crate::sandbox::linux::bridge::SocatBridge;
use crate::sandbox::linux::filesystem::{generate_bind_mounts, BindMount};
use crate::sandbox::linux::seccomp::{get_apply_seccomp_path, get_bpf_path};
use crate::utils::quote;

/// Check if bubblewrap is available.
pub fn check_bwrap() -> bool {
    std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Generate the bubblewrap command for sandboxed execution.
pub fn generate_bwrap_command(
    command: &str,
    config: &SandboxRuntimeConfig,
    cwd: &Path,
    http_socket_path: Option<&str>,
    socks_socket_path: Option<&str>,
    http_proxy_port: u16,
    socks_proxy_port: u16,
    shell: Option<&str>,
) -> Result<(String, Vec<String>), SandboxError> {
    let shell = shell.unwrap_or("/bin/bash");

    // Generate filesystem mounts
    let (mounts, warnings) = generate_bind_mounts(
        &config.filesystem,
        cwd,
        config.ripgrep.as_ref(),
        config.mandatory_deny_search_depth,
    )?;

    // Build bwrap arguments
    let mut bwrap_args = vec![
        "bwrap".to_string(),
        "--unshare-net".to_string(), // Network isolation
        "--proc".to_string(),
        "/proc".to_string(),
        "--tmpfs".to_string(),
        "/tmp".to_string(),
        "--tmpfs".to_string(),
        "/run".to_string(),
    ];

    // Start with read-only root filesystem
    bwrap_args.push("--ro-bind".to_string());
    bwrap_args.push("/".to_string());
    bwrap_args.push("/".to_string());

    // Re-apply /dev after the readonly root bind so device nodes keep working.
    bwrap_args.push("--dev".to_string());
    bwrap_args.push("/dev".to_string());

    // Add writable mounts
    for mount in &mounts {
        if !mount.readonly {
            bwrap_args.extend(mount.to_bwrap_args());
        }
    }

    // Add read-only (deny) mounts to override writable ones
    for mount in &mounts {
        if mount.readonly {
            bwrap_args.extend(mount.to_bwrap_args());
        }
    }

    // Set working directory
    bwrap_args.push("--chdir".to_string());
    bwrap_args.push(cwd.display().to_string());

    // Build the inner command with socat bridges and seccomp
    let inner_command = build_inner_command(
        command,
        config,
        http_socket_path,
        socks_socket_path,
        http_proxy_port,
        socks_proxy_port,
        shell,
    )?;

    // Add the command
    bwrap_args.push("--".to_string());
    bwrap_args.push(shell.to_string());
    bwrap_args.push("-c".to_string());
    bwrap_args.push(inner_command);

    // Join into a single command string
    let wrapped = bwrap_args
        .iter()
        .map(|s| quote(s))
        .collect::<Vec<_>>()
        .join(" ");

    Ok((wrapped, warnings))
}

/// Build the inner command to run inside bubblewrap.
/// This sets up socat bridges and applies seccomp before running the user command.
fn build_inner_command(
    command: &str,
    config: &SandboxRuntimeConfig,
    http_socket_path: Option<&str>,
    socks_socket_path: Option<&str>,
    http_proxy_port: u16,
    socks_proxy_port: u16,
    shell: &str,
) -> Result<String, SandboxError> {
    let mut parts = Vec::new();

    // Set up socat bridges for proxy access
    if let Some(http_sock) = http_socket_path {
        let bridge_cmd = SocatBridge::tcp_to_unix_command(http_proxy_port, http_sock);
        parts.push(format!("{} &", bridge_cmd));
    }

    if let Some(socks_sock) = socks_socket_path {
        let bridge_cmd = SocatBridge::tcp_to_unix_command(socks_proxy_port, socks_sock);
        parts.push(format!("{} &", bridge_cmd));
    }

    // Small delay to let socat bridges start
    if http_socket_path.is_some() || socks_socket_path.is_some() {
        parts.push("sleep 0.1".to_string());
    }

    // Apply seccomp filter and execute command
    if !config.network.allow_all_unix_sockets.unwrap_or(false) {
        // Try to use seccomp to block Unix socket creation
        if let (Ok(bpf_path), Ok(apply_path)) = (
            get_bpf_path(config.seccomp.as_ref()),
            get_apply_seccomp_path(config.seccomp.as_ref()),
        ) {
            // Export proxy environment variables before applying seccomp
            let env_vars = generate_proxy_env_string(http_proxy_port, socks_proxy_port);
            parts.push(env_vars);

            // Use apply-seccomp to apply the filter and exec the command
            parts.push(format!(
                "{} {} {} -c {}",
                apply_path.display(),
                bpf_path.display(),
                shell,
                quote(command)
            ));
        } else {
            // Seccomp not available, just run the command with warning
            tracing::warn!(
                "Seccomp not available - Unix socket creation will not be blocked"
            );
            let env_vars = generate_proxy_env_string(http_proxy_port, socks_proxy_port);
            parts.push(format!("{} {} -c {}", env_vars, shell, quote(command)));
        }
    } else {
        // Unix sockets allowed, just run the command
        let env_vars = generate_proxy_env_string(http_proxy_port, socks_proxy_port);
        parts.push(format!("{} {} -c {}", env_vars, shell, quote(command)));
    }

    Ok(parts.join("\n"))
}

/// Generate proxy environment variable exports.
fn generate_proxy_env_string(http_port: u16, socks_port: u16) -> String {
    format!(
        "export http_proxy='http://localhost:{}' https_proxy='http://localhost:{}' \
         HTTP_PROXY='http://localhost:{}' HTTPS_PROXY='http://localhost:{}' \
         ALL_PROXY='socks5://localhost:{}' all_proxy='socks5://localhost:{}'",
        http_port, http_port, http_port, http_port, socks_port, socks_port
    )
}

/// Generate proxy environment variables.
pub fn generate_proxy_env(http_port: u16, socks_port: u16) -> Vec<(String, String)> {
    let http_proxy = format!("http://localhost:{}", http_port);
    let socks_proxy = format!("socks5://localhost:{}", socks_port);

    vec![
        ("http_proxy".to_string(), http_proxy.clone()),
        ("HTTP_PROXY".to_string(), http_proxy.clone()),
        ("https_proxy".to_string(), http_proxy.clone()),
        ("HTTPS_PROXY".to_string(), http_proxy),
        ("ALL_PROXY".to_string(), socks_proxy.clone()),
        ("all_proxy".to_string(), socks_proxy),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NetworkConfig, SandboxRuntimeConfig};
    use std::process::Command;

    #[test]
    fn test_generate_proxy_env_string() {
        let env = generate_proxy_env_string(3128, 1080);
        assert!(env.contains("http_proxy='http://localhost:3128'"));
        assert!(env.contains("ALL_PROXY='socks5://localhost:1080'"));
    }

    #[test]
    fn test_build_inner_command_avoids_invalid_shell_separators() {
        let config = SandboxRuntimeConfig {
            network: NetworkConfig {
                allow_all_unix_sockets: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };

        let inner = build_inner_command(
            "ffmpeg -version && which ffmpeg",
            &config,
            Some("/tmp/srt-http-test.sock"),
            Some("/tmp/srt-socks-test.sock"),
            46807,
            36713,
            "/bin/bash",
        )
        .expect("inner command should build");

        assert!(!inner.contains("& ;"), "unexpected '& ;' in: {inner}");
        assert!(!inner.contains("; ;"), "unexpected '; ;' in: {inner}");

        let output = Command::new("/bin/bash")
            .args(["-n", "-c", &inner])
            .output()
            .expect("bash should be available");

        assert!(
            output.status.success(),
            "generated command should be valid shell, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn test_check_bwrap() {
        // This test will pass/fail based on system configuration
        let available = check_bwrap();
        println!("Bubblewrap available: {}", available);
    }

    #[test]
    fn test_generate_bwrap_command_mounts_dev_after_readonly_root() {
        let config = SandboxRuntimeConfig::default();
        let cwd = std::env::current_dir().expect("current dir should resolve");

        let (wrapped, warnings) = generate_bwrap_command(
            "echo hello",
            &config,
            &cwd,
            None,
            None,
            3128,
            1080,
            Some("/bin/bash"),
        )
        .expect("bwrap command should build");

        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");

        let root_bind = wrapped
            .find("'--ro-bind' '/' '/'")
            .expect("readonly root bind should exist");
        let dev_mount = wrapped
            .find("'--dev' '/dev'")
            .expect("/dev mount should exist");

        assert!(
            root_bind < dev_mount,
            "/dev mount must be applied after readonly root so /dev/null stays usable: {wrapped}"
        );
    }
}
