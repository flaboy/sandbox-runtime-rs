//! Filesystem bind mount generation for bubblewrap.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::config::{FilesystemConfig, RipgrepConfig, DANGEROUS_DIRECTORIES, DANGEROUS_FILES};
use crate::error::SandboxError;
use crate::utils::{
    contains_glob_chars, find_dangerous_files, is_symlink_outside_boundary,
    normalize_path_for_sandbox,
};

/// Bind mount specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindMountOp {
    ReadOnlyBind,
    WritableBind,
    DevNullBind,
    Tmpfs,
}

#[derive(Debug, Clone)]
pub struct BindMount {
    /// Source path on host.
    pub source: PathBuf,
    /// Target path in sandbox (usually same as source).
    pub target: PathBuf,
    /// Bubblewrap mount operation.
    pub op: BindMountOp,
    /// Whether the source path is a generated temporary projection.
    pub cleanup_source: bool,
    /// Whether the target directory should be created in the sandbox before binding.
    pub create_target_dir: bool,
}

impl BindMount {
    /// Create a new read-only bind mount.
    pub fn readonly(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            source: path.clone(),
            target: path,
            op: BindMountOp::ReadOnlyBind,
            cleanup_source: false,
            create_target_dir: false,
        }
    }

    /// Create a new writable bind mount.
    pub fn writable(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            source: path.clone(),
            target: path,
            op: BindMountOp::WritableBind,
            cleanup_source: false,
            create_target_dir: false,
        }
    }

    /// Create a dev-null mount to block a path.
    pub fn block(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            source: PathBuf::from("/dev/null"),
            target: path,
            op: BindMountOp::DevNullBind,
            cleanup_source: false,
            create_target_dir: false,
        }
    }

    /// Create a read-only alias bind from source to target.
    pub fn readonly_alias(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self::alias(source, target, false)
    }

    /// Create an alias bind from source to target.
    pub fn alias(source: impl Into<PathBuf>, target: impl Into<PathBuf>, writable: bool) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            op: if writable {
                BindMountOp::WritableBind
            } else {
                BindMountOp::ReadOnlyBind
            },
            cleanup_source: false,
            create_target_dir: true,
        }
    }

    /// Create a filtered alias root mount.
    pub fn filtered_alias_root(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            op: BindMountOp::ReadOnlyBind,
            cleanup_source: true,
            create_target_dir: true,
        }
    }

    /// Create a file bind inside a filtered alias root.
    pub fn filtered_alias_file(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            op: BindMountOp::ReadOnlyBind,
            cleanup_source: false,
            create_target_dir: false,
        }
    }

    /// Hide a source path with an empty tmpfs mount.
    pub fn hide_source_tmpfs(target: impl Into<PathBuf>) -> Self {
        let target = target.into();
        Self {
            source: target.clone(),
            target,
            op: BindMountOp::Tmpfs,
            cleanup_source: false,
            create_target_dir: false,
        }
    }

    pub fn is_writable_bind(&self) -> bool {
        self.op == BindMountOp::WritableBind
    }

    /// Convert to bwrap arguments.
    pub fn to_bwrap_args(&self) -> Vec<String> {
        let mut created_target_dirs = HashSet::new();
        self.to_bwrap_args_with_created_dirs(&mut created_target_dirs)
    }

    /// Convert to bwrap arguments, deduplicating generated target directories.
    pub fn to_bwrap_args_with_created_dirs(
        &self,
        created_target_dirs: &mut HashSet<PathBuf>,
    ) -> Vec<String> {
        let mut args = Vec::new();
        if self.create_target_dir {
            args.extend(target_dir_args(&self.target, created_target_dirs));
        }
        match self.op {
            BindMountOp::ReadOnlyBind => {
                args.push("--ro-bind".to_string());
                args.push(self.source.display().to_string());
                args.push(self.target.display().to_string());
            }
            BindMountOp::WritableBind => {
                args.push("--bind".to_string());
                args.push(self.source.display().to_string());
                args.push(self.target.display().to_string());
            }
            BindMountOp::DevNullBind => {
                args.push("--ro-bind".to_string());
                args.push("/dev/null".to_string());
                args.push(self.target.display().to_string());
            }
            BindMountOp::Tmpfs => {
                args.push("--tmpfs".to_string());
                args.push(self.target.display().to_string());
            }
        }
        args
    }
}

#[derive(Debug, Clone)]
struct AliasBind {
    source: PathBuf,
    target: PathBuf,
    writable: bool,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadDenyManifest {
    schema_version: u32,
    entries: Vec<ReadDenyManifestEntry>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadDenyManifestEntry {
    bind_target: String,
    relative_path: String,
}

fn target_dir_args(target: &Path, created_target_dirs: &mut HashSet<PathBuf>) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = PathBuf::new();
    let mut depth = 0usize;
    for component in target.components() {
        current.push(component.as_os_str());
        if current == Path::new("/") {
            continue;
        }
        depth += 1;
        if !created_target_dirs.insert(current.clone()) {
            continue;
        }
        if depth == 1 {
            args.push("--tmpfs".to_string());
        } else {
            args.push("--dir".to_string());
        }
        args.push(current.display().to_string());
    }
    args
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
            return Err(SandboxError::ExecutionFailed(format!(
                "Linux allowWrite glob patterns are not supported: {path}"
            )));
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
            return Err(SandboxError::ExecutionFailed(format!(
                "Linux denyWrite glob patterns are not supported: {path}"
            )));
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

    let alias_binds = normalize_alias_binds(config)?;
    validate_linux_glob_filter_contract(config)?;
    let bind_mounts = generate_alias_bind_mounts(config, &alias_binds)?;

    // Generate mounts
    mounts.extend(bind_mounts);

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
        if is_alias_target_path(path, &alias_binds) {
            continue;
        }
        if path.exists() {
            mounts.push(BindMount::readonly(path.clone()));
        } else {
            // Block non-existent paths with dev-null
            mounts.push(BindMount::block(path.clone()));
        }
    }

    Ok((mounts, warnings))
}

fn normalize_alias_binds(config: &FilesystemConfig) -> Result<Vec<AliasBind>, SandboxError> {
    let mut aliases = Vec::new();
    for bind in &config.binds {
        let source = normalize_bind_path(&bind.source, "source")?;
        let target = normalize_bind_path(&bind.target, "target")?;
        if source == target {
            return Err(SandboxError::ExecutionFailed(format!(
                "Filesystem bind source and target must differ: {}",
                source.display()
            )));
        }
        if !source.is_dir() {
            return Err(SandboxError::ExecutionFailed(format!(
                "Filesystem bind source must be an existing directory: {}",
                source.display()
            )));
        }
        aliases.push(AliasBind {
            source,
            target,
            writable: bind.writable.unwrap_or(false),
        });
    }
    Ok(aliases)
}

fn generate_alias_bind_mounts(
    config: &FilesystemConfig,
    aliases: &[AliasBind],
) -> Result<Vec<BindMount>, SandboxError> {
    let mut mounts = Vec::new();
    for alias in aliases {
        mounts.push(BindMount::alias(
            alias.source.clone(),
            alias.target.clone(),
            alias.writable,
        ));
        mounts.push(BindMount::hide_source_tmpfs(alias.source.clone()));
    }
    mounts.extend(generate_read_deny_manifest_mounts(config, aliases)?);
    Ok(mounts)
}

fn validate_linux_glob_filter_contract(config: &FilesystemConfig) -> Result<(), SandboxError> {
    if !config.deny_list_globs.is_empty() {
        return Err(SandboxError::ExecutionFailed(
            "denyListGlobs is not supported on linux; use denyReadManifest and allow list visibility"
                .to_string(),
        ));
    }

    if !config.deny_read_globs.is_empty()
        && config
            .deny_read_manifest
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
    {
        return Err(SandboxError::ExecutionFailed(
            "denyReadGlobs requires denyReadManifest on linux".to_string(),
        ));
    }

    Ok(())
}

fn normalize_bind_path(raw: &str, field: &str) -> Result<PathBuf, SandboxError> {
    if raw.trim().is_empty() {
        return Err(SandboxError::ExecutionFailed(format!(
            "Filesystem bind {field} is required"
        )));
    }
    if contains_glob_chars(raw) {
        return Err(SandboxError::ExecutionFailed(format!(
            "Filesystem bind {field} must not contain glob characters: {raw}"
        )));
    }
    let normalized = normalize_path_for_sandbox(raw);
    let path = PathBuf::from(&normalized);
    if !path.is_absolute() {
        return Err(SandboxError::ExecutionFailed(format!(
            "Filesystem bind {field} must be absolute: {raw}"
        )));
    }
    if path == Path::new("/") {
        return Err(SandboxError::ExecutionFailed(format!(
            "Filesystem bind {field} must not be /"
        )));
    }
    Ok(path)
}

fn is_alias_target_path(path: &Path, aliases: &[AliasBind]) -> bool {
    aliases.iter().any(|alias| path.starts_with(&alias.target))
}

fn generate_read_deny_manifest_mounts(
    config: &FilesystemConfig,
    aliases: &[AliasBind],
) -> Result<Vec<BindMount>, SandboxError> {
    let Some(manifest_path) = config.deny_read_manifest.as_deref().map(str::trim) else {
        return Ok(Vec::new());
    };
    if manifest_path.is_empty() {
        return Err(SandboxError::ExecutionFailed(
            "denyReadManifest must not be empty".to_string(),
        ));
    }

    let manifest_content = fs::read_to_string(manifest_path).map_err(|err| {
        SandboxError::ExecutionFailed(format!(
            "Failed to read denyReadManifest '{}': {}",
            manifest_path, err
        ))
    })?;
    let manifest: ReadDenyManifest = serde_json::from_str(&manifest_content).map_err(|err| {
        SandboxError::ExecutionFailed(format!(
            "Failed to parse denyReadManifest '{}': {}",
            manifest_path, err
        ))
    })?;
    if manifest.schema_version != 1 {
        return Err(SandboxError::ExecutionFailed(format!(
            "denyReadManifest unsupported schemaVersion: {}",
            manifest.schema_version
        )));
    }

    let alias_by_target = aliases
        .iter()
        .map(|alias| (alias.target.clone(), alias))
        .collect::<HashMap<_, _>>();
    let mut mounts = Vec::new();
    for entry in manifest.entries {
        let bind_target = PathBuf::from(normalize_path_for_sandbox(&entry.bind_target));
        let Some(alias) = alias_by_target.get(&bind_target) else {
            return Err(SandboxError::ExecutionFailed(format!(
                "denyReadManifest references unknown bind target: {}",
                entry.bind_target
            )));
        };
        if alias.writable {
            return Err(SandboxError::ExecutionFailed(format!(
                "Writable filesystem bind cannot use denyReadManifest: {} -> {}",
                alias.source.display(),
                alias.target.display()
            )));
        }

        let relative = validate_manifest_relative_path(&entry.relative_path)?;
        if relative.extension().and_then(|value| value.to_str()) != Some("md") {
            return Err(SandboxError::ExecutionFailed(format!(
                "denyReadManifest entry must target .md: {}",
                entry.relative_path
            )));
        }

        mounts.push(BindMount::block(alias.target.join(relative)));
    }

    Ok(mounts)
}

fn validate_manifest_relative_path(raw: &str) -> Result<PathBuf, SandboxError> {
    let path = Path::new(raw);
    if raw.trim().is_empty() || path.is_absolute() {
        return Err(SandboxError::ExecutionFailed(format!(
            "denyReadManifest entry escapes bind target: {raw}"
        )));
    }

    let mut has_component = false;
    for component in path.components() {
        match component {
            Component::Normal(_) => has_component = true,
            _ => {
                return Err(SandboxError::ExecutionFailed(format!(
                    "denyReadManifest entry escapes bind target: {raw}"
                )));
            }
        }
    }
    if !has_component {
        return Err(SandboxError::ExecutionFailed(format!(
            "denyReadManifest entry escapes bind target: {raw}"
        )));
    }

    Ok(path.to_path_buf())
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
    fn test_generate_bind_mounts_rejects_deny_list_globs_before_projection() {
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

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("denyListGlobs is not supported on linux"),
            "{err}"
        );
    }

    #[test]
    fn test_linux_rejects_deny_list_globs() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("skill");
        std::fs::create_dir_all(&source_root).unwrap();

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/demo".to_string(),
                writable: Some(false),
            }],
            deny_list_globs: vec!["/skills/demo/**/*.md".to_string()],
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("denyListGlobs is not supported on linux"),
            "{err}"
        );
    }

    #[test]
    fn test_linux_rejects_deny_read_globs_without_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("skill");
        std::fs::create_dir_all(&source_root).unwrap();

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/demo".to_string(),
                writable: Some(false),
            }],
            deny_read_globs: vec!["/skills/demo/**/*.md".to_string()],
            deny_read_manifest: None,
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("denyReadGlobs requires denyReadManifest"),
            "{err}"
        );
    }

    #[test]
    fn test_deny_read_manifest_does_not_create_filtered_alias() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("mounted").join("skills").join("triage");
        std::fs::create_dir_all(source_root.join("scripts")).unwrap();
        std::fs::create_dir_all(source_root.join("references")).unwrap();
        std::fs::write(source_root.join("SKILL.md"), "hidden skill doc").unwrap();
        std::fs::write(
            source_root.join("references").join("policy.md"),
            "hidden policy",
        )
        .unwrap();
        std::fs::write(
            source_root.join("scripts").join("classify.js"),
            "console.log('allowed');",
        )
        .unwrap();
        let manifest = temp.path().join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{
                "schemaVersion": 1,
                "entries": [
                    {"bindTarget": "/skills/triage", "relativePath": "SKILL.md"},
                    {"bindTarget": "/skills/triage", "relativePath": "references/policy.md"}
                ]
            }"#,
        )
        .unwrap();

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/triage".to_string(),
                writable: Some(false),
            }],
            deny_read_globs: vec!["/skills/triage/**/*.md".to_string()],
            deny_read_manifest: Some(manifest.display().to_string()),
            ..Default::default()
        };

        let (mounts, warnings) = generate_bind_mounts(&config, temp.path(), None, None).unwrap();

        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(
            mounts.iter().all(|mount| !mount
                .source
                .display()
                .to_string()
                .contains("srt-filtered-alias")),
            "read deny manifest must not use filtered alias source mounts: {mounts:?}"
        );
        assert!(
            mounts.iter().any(|mount| mount.source == source_root
                && mount.target == Path::new("/skills/triage")
                && mount.op == BindMountOp::ReadOnlyBind),
            "source root should be mounted directly as ordinary readonly alias"
        );
        assert!(
            mounts
                .iter()
                .any(|mount| mount.source == Path::new("/dev/null")
                    && mount.target == Path::new("/skills/triage/SKILL.md")
                    && mount.op == BindMountOp::DevNullBind),
            "manifest markdown file should be blocked by dev-null overlay"
        );
        assert!(
            mounts
                .iter()
                .any(|mount| mount.source == Path::new("/dev/null")
                    && mount.target == Path::new("/skills/triage/references/policy.md")
                    && mount.op == BindMountOp::DevNullBind),
            "nested manifest markdown file should be blocked by dev-null overlay"
        );
    }

    #[test]
    fn test_linux_rejects_deny_read_globs_without_manifest_for_alias() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("skill");
        std::fs::create_dir_all(&source_root).unwrap();

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/triage".to_string(),
                writable: Some(false),
            }],
            deny_read_globs: vec!["/skills/triage/**/*.md".to_string()],
            deny_list_globs: vec![],
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("denyReadGlobs requires denyReadManifest"),
            "{err}"
        );
    }

    #[test]
    fn test_linux_rejects_deny_list_globs_for_non_alias_globs() {
        let temp = tempfile::tempdir().unwrap();
        let loose_root = temp.path().join("loose");
        std::fs::create_dir_all(&loose_root).unwrap();

        let pattern = format!("{}/**/*.md", loose_root.display());
        let config = FilesystemConfig {
            deny_read_globs: vec![pattern.clone()],
            deny_list_globs: vec![pattern],
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("denyListGlobs is not supported on linux"),
            "{err}"
        );
    }

    #[test]
    fn test_linux_allow_write_glob_fastfails() {
        let temp = tempfile::tempdir().unwrap();
        let config = FilesystemConfig {
            allow_write: vec!["/tmp/**/*.tmp".to_string()],
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("Linux allowWrite glob patterns are not supported: /tmp/**/*.tmp"),
            "{err}"
        );
    }

    #[test]
    fn test_linux_deny_write_glob_fastfails() {
        let temp = tempfile::tempdir().unwrap();
        let config = FilesystemConfig {
            deny_write: vec!["/tmp/**/*.tmp".to_string()],
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("Linux denyWrite glob patterns are not supported: /tmp/**/*.tmp"),
            "{err}"
        );
    }

    #[test]
    fn test_deny_read_manifest_rejects_writable_alias() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("skill");
        std::fs::create_dir_all(&source_root).unwrap();
        std::fs::write(source_root.join("SKILL.md"), "skill").unwrap();
        let manifest = temp.path().join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{
                "schemaVersion": 1,
                "entries": [
                    {"bindTarget": "/skills/triage", "relativePath": "SKILL.md"}
                ]
            }"#,
        )
        .unwrap();

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/triage".to_string(),
                writable: Some(true),
            }],
            deny_read_globs: vec!["/skills/triage/**/*.md".to_string()],
            deny_read_manifest: Some(manifest.display().to_string()),
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("Writable filesystem bind cannot use denyReadManifest"),
            "{err}"
        );
    }

    #[test]
    fn test_deny_read_manifest_rejects_exact_alias_root_entry() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("skill");
        std::fs::create_dir_all(&source_root).unwrap();
        let manifest = temp.path().join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{
                "schemaVersion": 1,
                "entries": [
                    {"bindTarget": "/skills/triage", "relativePath": "."}
                ]
            }"#,
        )
        .unwrap();

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/triage".to_string(),
                writable: Some(false),
            }],
            deny_read_globs: vec!["/skills/triage".to_string()],
            deny_read_manifest: Some(manifest.display().to_string()),
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("denyReadManifest entry escapes bind target"),
            "{err}"
        );
    }

    #[test]
    fn test_deny_read_manifest_rejects_path_traversal() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("skill");
        std::fs::create_dir_all(&source_root).unwrap();
        std::fs::write(source_root.join("SKILL.md"), "skill").unwrap();
        let manifest = temp.path().join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{
                "schemaVersion": 1,
                "entries": [
                    {"bindTarget": "/skills/triage", "relativePath": "../SKILL.md"}
                ]
            }"#,
        )
        .unwrap();

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/triage".to_string(),
                writable: Some(false),
            }],
            deny_read_globs: vec!["/skills/triage/**/*.md".to_string()],
            deny_read_manifest: Some(manifest.display().to_string()),
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("denyReadManifest entry escapes bind target"),
            "{err}"
        );
    }

    #[test]
    fn test_deny_read_manifest_rejects_unknown_bind_target() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("skill");
        std::fs::create_dir_all(&source_root).unwrap();
        std::fs::write(source_root.join("SKILL.md"), "skill").unwrap();
        let manifest = temp.path().join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{
                "schemaVersion": 1,
                "entries": [
                    {"bindTarget": "/skills/other", "relativePath": "SKILL.md"}
                ]
            }"#,
        )
        .unwrap();

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/triage".to_string(),
                writable: Some(false),
            }],
            deny_read_globs: vec!["/skills/triage/**/*.md".to_string()],
            deny_read_manifest: Some(manifest.display().to_string()),
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("denyReadManifest references unknown bind target"),
            "{err}"
        );
    }

    #[test]
    fn test_deny_read_manifest_rejects_non_markdown_entry() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("skill");
        std::fs::create_dir_all(&source_root).unwrap();
        std::fs::write(source_root.join("tool.json"), "{}").unwrap();
        let manifest = temp.path().join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{
                "schemaVersion": 1,
                "entries": [
                    {"bindTarget": "/skills/triage", "relativePath": "tool.json"}
                ]
            }"#,
        )
        .unwrap();

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/triage".to_string(),
                writable: Some(false),
            }],
            deny_read_globs: vec!["/skills/triage/**/*.md".to_string()],
            deny_read_manifest: Some(manifest.display().to_string()),
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("denyReadManifest entry must target .md"),
            "{err}"
        );
    }

    #[test]
    fn test_deny_read_manifest_does_not_stat_source_file() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("skill");
        std::fs::create_dir_all(&source_root).unwrap();
        let manifest = temp.path().join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{
                "schemaVersion": 1,
                "entries": [
                    {"bindTarget": "/skills/triage", "relativePath": "missing.md"}
                ]
            }"#,
        )
        .unwrap();

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/triage".to_string(),
                writable: Some(false),
            }],
            deny_read_globs: vec!["/skills/triage/**/*.md".to_string()],
            deny_read_manifest: Some(manifest.display().to_string()),
            ..Default::default()
        };

        let (mounts, warnings) = generate_bind_mounts(&config, temp.path(), None, None).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(
            mounts.iter().any(|mount| {
                mount.source == PathBuf::from("/dev/null")
                    && mount.target == PathBuf::from("/skills/triage/missing.md")
            }),
            "{mounts:?}"
        );
    }
}
