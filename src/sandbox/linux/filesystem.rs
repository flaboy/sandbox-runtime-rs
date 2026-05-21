//! Filesystem bind mount generation for bubblewrap.

use std::collections::HashSet;
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

#[derive(Debug)]
struct FilteredAliasPlan {
    skeleton_root: PathBuf,
    file_mounts: Vec<BindMount>,
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
    validate_linux_glob_filter_contract(config, &alias_binds)?;
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
    let patterns = filesystem_projection_patterns(config);
    for alias in aliases {
        let translated_patterns = translate_alias_patterns(&patterns, alias)?;
        if translated_patterns.is_empty() {
            mounts.push(BindMount::alias(
                alias.source.clone(),
                alias.target.clone(),
                alias.writable,
            ));
        } else {
            if alias.writable {
                return Err(SandboxError::ExecutionFailed(format!(
                    "Writable filesystem bind cannot use read/list glob filtering: {} -> {}",
                    alias.source.display(),
                    alias.target.display()
                )));
            }
            let plan =
                create_filtered_alias_plan(&alias.source, &alias.target, &translated_patterns)?;
            mounts.push(BindMount::filtered_alias_root(
                plan.skeleton_root,
                alias.target.clone(),
            ));
            mounts.extend(plan.file_mounts);
        }
        mounts.push(BindMount::hide_source_tmpfs(alias.source.clone()));
    }
    Ok(mounts)
}

fn validate_linux_glob_filter_contract(
    config: &FilesystemConfig,
    aliases: &[AliasBind],
) -> Result<(), SandboxError> {
    let read_globs = config
        .deny_read_globs
        .iter()
        .map(|pattern| normalize_path_for_sandbox(pattern))
        .collect::<Vec<_>>();
    let list_globs = config
        .deny_list_globs
        .iter()
        .map(|pattern| normalize_path_for_sandbox(pattern))
        .collect::<Vec<_>>();

    if read_globs != list_globs {
        return Err(SandboxError::ExecutionFailed(
            "Linux read/list glob filtering requires identical denyReadGlobs and denyListGlobs"
                .to_string(),
        ));
    }

    for pattern in read_globs {
        let matching_aliases = aliases
            .iter()
            .filter(|alias| pattern_targets_alias(&pattern, &alias.target))
            .collect::<Vec<_>>();

        match matching_aliases.as_slice() {
            [] => {
                return Err(SandboxError::ExecutionFailed(
                    "Linux read/list glob filtering is only supported for filesystem.binds aliases"
                        .to_string(),
                ));
            }
            [alias] if alias.writable => {
                return Err(SandboxError::ExecutionFailed(format!(
                    "Writable filesystem bind cannot use read/list glob filtering: {} -> {}",
                    alias.source.display(),
                    alias.target.display()
                )));
            }
            [alias] if pattern == alias.target.display().to_string() => {
                return Err(SandboxError::ExecutionFailed(format!(
                    "Linux read/list glob filtering cannot target alias root exactly: {pattern}"
                )));
            }
            [_] => {}
            _ => {
                return Err(SandboxError::ExecutionFailed(format!(
                    "Linux read/list glob pattern targets multiple filesystem.binds aliases: {pattern}"
                )));
            }
        }
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

fn filesystem_projection_patterns(config: &FilesystemConfig) -> Vec<String> {
    let mut patterns = Vec::new();
    patterns.extend(config.deny_read_globs.iter().cloned());
    patterns.extend(config.deny_list_globs.iter().cloned());
    patterns
}

fn translate_alias_patterns(
    patterns: &[String],
    alias: &AliasBind,
) -> Result<Vec<glob::Pattern>, SandboxError> {
    let mut out = Vec::new();
    for pattern in patterns {
        let normalized = normalize_path_for_sandbox(pattern);
        let Some(translated) = rewrite_alias_pattern(&normalized, &alias.target, &alias.source)
        else {
            continue;
        };
        let compiled = glob::Pattern::new(&translated).map_err(|err| {
            SandboxError::ExecutionFailed(format!(
                "Invalid filesystem glob pattern '{}': {}",
                pattern, err
            ))
        })?;
        out.push(compiled);
    }
    Ok(out)
}

fn rewrite_alias_pattern(pattern: &str, target: &Path, source: &Path) -> Option<String> {
    if !pattern_targets_alias(pattern, target) {
        return None;
    }
    let target = target.display().to_string();
    let source = source.display().to_string();
    if pattern == target {
        return Some(source);
    }
    Some(format!("{}{}", source, &pattern[target.len()..]))
}

fn pattern_targets_alias(pattern: &str, target: &Path) -> bool {
    let target = target.display().to_string();
    pattern == target || pattern.starts_with(&format!("{target}/"))
}

fn is_alias_target_path(path: &Path, aliases: &[AliasBind]) -> bool {
    aliases.iter().any(|alias| path.starts_with(&alias.target))
}

fn create_filtered_alias_plan(
    source_root: &Path,
    target_root: &Path,
    denied_patterns: &[glob::Pattern],
) -> Result<FilteredAliasPlan, SandboxError> {
    reject_filtered_alias_symlinks(source_root)?;
    let id = PROJECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let skeleton_root =
        std::env::temp_dir().join(format!("srt-filtered-alias-{}-{}", std::process::id(), id));
    if skeleton_root.exists() {
        fs::remove_dir_all(&skeleton_root)?;
    }
    fs::create_dir_all(&skeleton_root)?;
    let mut file_mounts = Vec::new();
    build_filtered_alias_tree(
        source_root,
        source_root,
        target_root,
        &skeleton_root,
        denied_patterns,
        &mut file_mounts,
    )?;
    Ok(FilteredAliasPlan {
        skeleton_root,
        file_mounts,
    })
}

fn reject_filtered_alias_symlinks(current: &Path) -> Result<(), SandboxError> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let source_path = entry.path();
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            return Err(SandboxError::ExecutionFailed(format!(
                "Filtered filesystem bind does not support symlinks: {}",
                source_path.display()
            )));
        }
        if metadata.is_dir() {
            reject_filtered_alias_symlinks(&source_path)?;
        }
    }
    Ok(())
}

fn build_filtered_alias_tree(
    source_root: &Path,
    current: &Path,
    target_root: &Path,
    skeleton_root: &Path,
    denied_patterns: &[glob::Pattern],
    file_mounts: &mut Vec<BindMount>,
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
        let skeleton_path = skeleton_root.join(relative);
        let sandbox_path = target_root.join(relative);
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.is_dir() {
            fs::create_dir_all(&skeleton_path)?;
            fs::set_permissions(&skeleton_path, metadata.permissions())?;
            build_filtered_alias_tree(
                source_root,
                &source_path,
                target_root,
                skeleton_root,
                denied_patterns,
                file_mounts,
            )?;
        } else if metadata.file_type().is_symlink() {
            return Err(SandboxError::ExecutionFailed(format!(
                "Filtered filesystem bind does not support symlinks: {}",
                source_path.display()
            )));
        } else if metadata.is_file() {
            if let Some(parent) = skeleton_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::File::create(&skeleton_path)?;
            fs::set_permissions(&skeleton_path, metadata.permissions())?;
            file_mounts.push(BindMount::filtered_alias_file(source_path, sandbox_path));
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
    fn test_generate_bind_mounts_rejects_non_alias_denied_markdown_globs() {
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
            err.to_string().contains(
                "Linux read/list glob filtering is only supported for filesystem.binds aliases"
            ),
            "{err}"
        );
    }

    #[test]
    fn test_filtered_alias_bind_does_not_create_copy_projection() {
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

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/triage".to_string(),
                writable: Some(false),
            }],
            deny_read_globs: vec!["/skills/triage/**/*.md".to_string()],
            deny_list_globs: vec!["/skills/triage/**/*.md".to_string()],
            ..Default::default()
        };

        let (mounts, warnings) = generate_bind_mounts(&config, temp.path(), None, None).unwrap();

        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(
            mounts.iter().all(|mount| !mount
                .source
                .display()
                .to_string()
                .contains("srt-projection-")),
            "filtered alias must not use copy projection mounts: {mounts:?}"
        );
        assert!(
            mounts
                .iter()
                .any(|mount| mount.target == Path::new("/skills/triage/scripts/classify.js")),
            "allowed file should be mounted directly into filtered alias"
        );
        assert!(
            mounts
                .iter()
                .all(|mount| mount.target != Path::new("/skills/triage/SKILL.md")),
            "denied markdown file must not be mounted"
        );
    }

    #[test]
    fn test_filtered_alias_rejects_asymmetric_read_and_list_globs() {
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
            err.to_string().contains(
                "Linux read/list glob filtering requires identical denyReadGlobs and denyListGlobs"
            ),
            "{err}"
        );
    }

    #[test]
    fn test_filtered_alias_rejects_non_alias_globs() {
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
            err.to_string().contains(
                "Linux read/list glob filtering is only supported for filesystem.binds aliases"
            ),
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
    fn test_filtered_alias_rejects_writable_alias() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("skill");
        std::fs::create_dir_all(&source_root).unwrap();

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/triage".to_string(),
                writable: Some(true),
            }],
            deny_read_globs: vec!["/skills/triage/**/*.md".to_string()],
            deny_list_globs: vec!["/skills/triage/**/*.md".to_string()],
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("Writable filesystem bind cannot use read/list glob filtering"),
            "{err}"
        );
    }

    #[test]
    fn test_filtered_alias_rejects_exact_alias_root_glob() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("skill");
        std::fs::create_dir_all(&source_root).unwrap();

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/triage".to_string(),
                writable: Some(false),
            }],
            deny_read_globs: vec!["/skills/triage".to_string()],
            deny_list_globs: vec!["/skills/triage".to_string()],
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("Linux read/list glob filtering cannot target alias root exactly"),
            "{err}"
        );
    }

    #[test]
    fn test_filtered_alias_rejects_denied_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("skill");
        std::fs::create_dir_all(&source_root).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", source_root.join("hidden.md")).unwrap();

        let config = FilesystemConfig {
            binds: vec![crate::config::schema::FilesystemBindConfig {
                source: source_root.display().to_string(),
                target: "/skills/triage".to_string(),
                writable: Some(false),
            }],
            deny_read_globs: vec!["/skills/triage/**/*.md".to_string()],
            deny_list_globs: vec!["/skills/triage/**/*.md".to_string()],
            ..Default::default()
        };

        let err = generate_bind_mounts(&config, temp.path(), None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("Filtered filesystem bind does not support symlinks"),
            "{err}"
        );
    }
}
