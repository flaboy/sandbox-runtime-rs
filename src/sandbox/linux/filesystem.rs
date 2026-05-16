//! Filesystem bind mount generation for bubblewrap.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::{FilesystemConfig, RipgrepConfig, DANGEROUS_DIRECTORIES, DANGEROUS_FILES};
use crate::error::SandboxError;
use crate::utils::{
    contains_glob_chars, find_dangerous_files, is_symlink_outside_boundary,
    normalize_path_for_sandbox,
};

static PROJECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Bind mount specification.
#[derive(Debug, Clone)]
pub struct BindMount {
    /// Source path on host.
    pub source: PathBuf,
    /// Target path in sandbox (usually same as source).
    pub target: PathBuf,
    /// Whether the mount is read-only.
    pub readonly: bool,
    /// Whether to create the path with dev-null if it doesn't exist.
    pub dev_null: bool,
    /// Whether the source path is a generated temporary projection.
    pub cleanup_source: bool,
}

impl BindMount {
    /// Create a new read-only bind mount.
    pub fn readonly(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            source: path.clone(),
            target: path,
            readonly: true,
            dev_null: false,
            cleanup_source: false,
        }
    }

    /// Create a new writable bind mount.
    pub fn writable(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            source: path.clone(),
            target: path,
            readonly: false,
            dev_null: false,
            cleanup_source: false,
        }
    }

    /// Create a dev-null mount to block a path.
    pub fn block(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            source: PathBuf::from("/dev/null"),
            target: path,
            readonly: true,
            dev_null: true,
            cleanup_source: false,
        }
    }

    /// Create a read-only projection mount that should be cleaned up after execution.
    pub fn projection(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            readonly: true,
            dev_null: false,
            cleanup_source: true,
        }
    }

    /// Convert to bwrap arguments.
    pub fn to_bwrap_args(&self) -> Vec<String> {
        if self.dev_null {
            vec![
                "--ro-bind".to_string(),
                "/dev/null".to_string(),
                self.target.display().to_string(),
            ]
        } else if self.readonly {
            vec![
                "--ro-bind".to_string(),
                self.source.display().to_string(),
                self.target.display().to_string(),
            ]
        } else {
            vec![
                "--bind".to_string(),
                self.source.display().to_string(),
                self.target.display().to_string(),
            ]
        }
    }
}

/// Generate bind mounts for the filesystem configuration.
pub fn generate_bind_mounts(
    config: &FilesystemConfig,
    cwd: &Path,
    ripgrep_config: Option<&RipgrepConfig>,
    max_depth: Option<u32>,
) -> Result<(Vec<BindMount>, Vec<String>), SandboxError> {
    let mut mounts = Vec::new();
    let mut warnings = Vec::new();

    // Collect all paths that need to be writable
    let mut writable_paths: HashSet<PathBuf> = HashSet::new();
    for path in &config.allow_write {
        // Handle glob patterns
        if contains_glob_chars(path) {
            warnings.push(format!(
                "Glob pattern '{}' is not supported on Linux; ignoring",
                path
            ));
            continue;
        }

        let normalized = normalize_path_for_sandbox(path);
        let path = PathBuf::from(&normalized);

        if path.exists() {
            writable_paths.insert(path);
        } else {
            warnings.push(format!("Write path '{}' does not exist", normalized));
        }
    }

    // Collect all paths that need to be denied write access
    let mut deny_paths: HashSet<PathBuf> = HashSet::new();
    for path in &config.deny_write {
        if contains_glob_chars(path) {
            warnings.push(format!(
                "Glob pattern '{}' is not supported on Linux; ignoring",
                path
            ));
            continue;
        }

        let normalized = normalize_path_for_sandbox(path);
        deny_paths.insert(PathBuf::from(&normalized));
    }

    // Find dangerous files using ripgrep
    let dangerous_files = find_dangerous_files(cwd, ripgrep_config, max_depth).unwrap_or_default();
    for file in dangerous_files {
        deny_paths.insert(PathBuf::from(file));
    }

    // Add mandatory deny paths
    for dir in DANGEROUS_DIRECTORIES {
        // Check in cwd
        let path = cwd.join(dir);
        if path.exists() {
            deny_paths.insert(path);
        }

        // Check in home
        if let Some(home) = dirs::home_dir() {
            let path = home.join(dir);
            if path.exists() {
                deny_paths.insert(path);
            }
        }
    }

    for file in DANGEROUS_FILES {
        // Skip .gitconfig if allowed
        if *file == ".gitconfig" && config.allow_git_config.unwrap_or(false) {
            continue;
        }

        if let Some(home) = dirs::home_dir() {
            let path = home.join(file);
            if path.exists() {
                deny_paths.insert(path);
            }
        }
    }

    let projection_mounts = generate_projection_mounts(config, &mut warnings)?;

    // Generate mounts
    mounts.extend(projection_mounts);

    // First, add writable mounts
    for path in &writable_paths {
        // Check for symlinks that might escape
        if let Ok(resolved) = std::fs::canonicalize(path) {
            if is_symlink_outside_boundary(path, &resolved) {
                mounts.push(BindMount::block(path.clone()));
                continue;
            }
        }

        mounts.push(BindMount::writable(path.clone()));
    }

    // Then, add deny mounts (these override writable mounts)
    for path in &deny_paths {
        if path.exists() {
            mounts.push(BindMount::readonly(path.clone()));
        } else {
            // Block non-existent paths with dev-null
            mounts.push(BindMount::block(path.clone()));
        }
    }

    Ok((mounts, warnings))
}

fn generate_projection_mounts(
    config: &FilesystemConfig,
    warnings: &mut Vec<String>,
) -> Result<Vec<BindMount>, SandboxError> {
    let mut patterns = Vec::new();
    patterns.extend(config.deny_read_globs.iter().cloned());
    patterns.extend(config.deny_list_globs.iter().cloned());
    if patterns.is_empty() {
        return Ok(Vec::new());
    }

    let mut grouped_patterns: BTreeMap<PathBuf, Vec<glob::Pattern>> = BTreeMap::new();
    for pattern in patterns {
        let normalized = normalize_path_for_sandbox(&pattern);
        let Some(root) = glob_projection_root(&normalized) else {
            warnings.push(format!(
                "Glob pattern '{}' is too broad for Linux projection; ignoring",
                pattern
            ));
            continue;
        };
        if !root.is_dir() {
            warnings.push(format!(
                "Glob pattern '{}' projection root '{}' does not exist or is not a directory",
                pattern,
                root.display()
            ));
            continue;
        }
        let compiled = glob::Pattern::new(&normalized).map_err(|err| {
            SandboxError::ExecutionFailed(format!(
                "Invalid filesystem glob pattern '{}': {}",
                pattern, err
            ))
        })?;
        grouped_patterns.entry(root).or_default().push(compiled);
    }

    let mut mounts = Vec::new();
    for (root, compiled_patterns) in grouped_patterns {
        let projection_root = create_projection_root(&root, &compiled_patterns)?;
        mounts.push(BindMount::projection(projection_root, root));
    }
    Ok(mounts)
}

fn glob_projection_root(pattern: &str) -> Option<PathBuf> {
    let path = Path::new(pattern);
    let mut root = PathBuf::new();
    for component in path.components() {
        let component_text = component.as_os_str().to_string_lossy();
        if contains_glob_chars(&component_text) {
            break;
        }
        root.push(component.as_os_str());
    }

    if root.as_os_str().is_empty() || root == Path::new("/") {
        None
    } else {
        Some(root)
    }
}

fn create_projection_root(
    source_root: &Path,
    denied_patterns: &[glob::Pattern],
) -> Result<PathBuf, SandboxError> {
    let id = PROJECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let projection_root =
        std::env::temp_dir().join(format!("srt-projection-{}-{}", std::process::id(), id));
    if projection_root.exists() {
        fs::remove_dir_all(&projection_root)?;
    }
    fs::create_dir_all(&projection_root)?;
    copy_projection_tree(source_root, source_root, &projection_root, denied_patterns)?;
    Ok(projection_root)
}

fn copy_projection_tree(
    source_root: &Path,
    current: &Path,
    target_root: &Path,
    denied_patterns: &[glob::Pattern],
) -> Result<(), SandboxError> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let source_path = entry.path();
        if denied_patterns
            .iter()
            .any(|pattern| pattern.matches_path(&source_path))
        {
            continue;
        }

        let relative = source_path.strip_prefix(source_root).map_err(|err| {
            SandboxError::ExecutionFailed(format!(
                "Failed to project filesystem path '{}': {}",
                source_path.display(),
                err
            ))
        })?;
        let target_path = target_root.join(relative);
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.is_dir() {
            fs::create_dir_all(&target_path)?;
            fs::set_permissions(&target_path, metadata.permissions())?;
            copy_projection_tree(source_root, &source_path, target_root, denied_patterns)?;
        } else if metadata.file_type().is_symlink() {
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(fs::read_link(&source_path)?, &target_path)?;
            }
        } else if metadata.is_file() {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source_path, &target_path)?;
            fs::set_permissions(&target_path, metadata.permissions())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_mount_to_bwrap_args() {
        let mount = BindMount::readonly("/path/to/file");
        let args = mount.to_bwrap_args();
        assert_eq!(args, vec!["--ro-bind", "/path/to/file", "/path/to/file"]);

        let mount = BindMount::writable("/path/to/dir");
        let args = mount.to_bwrap_args();
        assert_eq!(args, vec!["--bind", "/path/to/dir", "/path/to/dir"]);

        let mount = BindMount::block("/path/to/blocked");
        let args = mount.to_bwrap_args();
        assert_eq!(args, vec!["--ro-bind", "/dev/null", "/path/to/blocked"]);
    }

    #[test]
    fn test_generate_bind_mounts_projects_denied_markdown_globs() {
        let temp = tempfile::tempdir().unwrap();
        let skill_root = temp.path().join("skills").join("triage");
        std::fs::create_dir_all(skill_root.join("references")).unwrap();
        std::fs::create_dir_all(skill_root.join("scripts")).unwrap();
        std::fs::write(skill_root.join("SKILL.md"), "skill").unwrap();
        std::fs::write(skill_root.join("references").join("policy.md"), "policy").unwrap();
        std::fs::write(skill_root.join("scripts").join("classify.js"), "script").unwrap();

        let config = FilesystemConfig {
            deny_read_globs: vec![format!("{}/**/*.md", skill_root.display())],
            deny_list_globs: vec![format!("{}/**/*.md", skill_root.display())],
            ..Default::default()
        };

        let (mounts, warnings) = generate_bind_mounts(&config, temp.path(), None, None).unwrap();

        assert!(warnings.is_empty(), "{warnings:?}");
        let projection = mounts
            .iter()
            .find(|mount| mount.cleanup_source && mount.target == skill_root)
            .expect("projection mount should be generated");
        assert!(projection
            .source
            .join("scripts")
            .join("classify.js")
            .exists());
        assert!(!projection.source.join("SKILL.md").exists());
        assert!(!projection
            .source
            .join("references")
            .join("policy.md")
            .exists());
        std::fs::remove_dir_all(&projection.source).unwrap();
    }
}
