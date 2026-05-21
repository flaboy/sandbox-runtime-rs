# SRT Linux Filtered Bind Sandbox Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove Linux copy-based filesystem projections for system skill read/list glob hiding and replace them with one native SRT/bubblewrap filtered bind path, verified in AWS `syngy-sgp` Kubernetes.

**Architecture:** Linux will support read/list glob filtering only through read-only `filesystem.binds` aliases. SRT will build a filtered alias skeleton containing allowed directory structure and empty placeholders, then overlay allowed files with read-only bind mounts; denied paths never exist in the sandbox view, so both read and directory listing are denied without copying file contents. Unsupported shapes fail before command execution; there is no projection fallback.

**Tech Stack:** Rust 2021, cargo test, bubblewrap, Kubernetes on AWS EKS `syngy-sgp`, `/Users/wanglei/Library/bin/kubectl`, kubeconfig `/Users/wanglei/.kube/config.d/syngy-sgp.yaml`.

---

## Current Evidence

- Local SRT repo: `/Users/wanglei/Projects/github-flaboy/sandbox-runtime-rs`.
- Current branch: `main`.
- Existing worktree already has unrelated modified files; do not overwrite or revert them.
- Linux filesystem implementation is in `src/sandbox/linux/filesystem.rs`.
- Current slow path:
  - `generate_alias_bind_mounts()` translates deny globs for each alias.
  - If translated patterns exist, it calls `create_projection_root()`.
  - `create_projection_root()` calls `copy_projection_tree()`.
  - `copy_projection_tree()` recursively copies all allowed files into `/tmp/srt-projection-*`.
- Current hidden-source path also creates `/tmp/srt-hidden-*`.
- AWS `syngy-sgp` access:
  - Context: `syngy-sgp`.
  - Kubeconfig: `/Users/wanglei/.kube/config.d/syngy-sgp.yaml`.
  - Kubectl: `/Users/wanglei/Library/bin/kubectl`.
  - Node OS: Amazon Linux 2023.
  - Kernel: `6.12.80-106.156.amzn2023.x86_64`.
  - Architecture: x86_64.
  - RBAC checked: can create pods, jobs, and pods/exec.

## Contract

This implementation must follow:

- **No fallback:** do not keep `copy_projection_tree()` as a backup path for Linux glob filtering.
- **Fastfail:** unsupported Linux filesystem policy shapes return `SandboxError::ExecutionFailed` before bwrap command generation finishes.
- **Single success path:** Linux glob read/list filtering succeeds only through filtered read-only alias binds.
- **Security before compatibility:** if semantics are ambiguous, fail with a clear message instead of approximating behavior.

Supported Linux glob filtering shape for this change:

- `filesystem.binds[]` entry is read-only.
- `denyReadGlobs` and `denyListGlobs` contain the same normalized patterns.
- Every deny glob targets exactly one alias target.
- Alias source is an existing directory.
- Alias source tree contains no symlinks when filtering is active.

Unsupported shapes must fail:

- Writable alias bind with matching read/list deny globs.
- Non-alias `denyReadGlobs` or `denyListGlobs`.
- `denyReadGlobs` and `denyListGlobs` differ.
- Glob pattern exactly equals an alias target.
- Glob pattern targets no alias or multiple aliases.
- Symlink found under a filtered alias source.
- Linux `allowWrite` or `denyWrite` glob patterns that are currently only warned and ignored.

## Task 1: Add RED Unit Tests for Filtered Alias Contract

**Files:**
- Modify: `/Users/wanglei/Projects/github-flaboy/sandbox-runtime-rs/src/sandbox/linux/filesystem.rs`

**Step 1: Add a failing test for no projection copy**

Add this test inside the existing `#[cfg(test)] mod tests`:

```rust
#[test]
fn test_filtered_alias_bind_does_not_create_copy_projection() {
    let temp = tempfile::tempdir().unwrap();
    let source_root = temp.path().join("mounted").join("skills").join("triage");
    std::fs::create_dir_all(source_root.join("scripts")).unwrap();
    std::fs::create_dir_all(source_root.join("references")).unwrap();
    std::fs::write(source_root.join("SKILL.md"), "hidden skill doc").unwrap();
    std::fs::write(source_root.join("references").join("policy.md"), "hidden policy").unwrap();
    std::fs::write(source_root.join("scripts").join("classify.js"), "console.log('allowed');").unwrap();

    let config = FilesystemConfig {
        binds: vec![crate::config::FilesystemBindConfig {
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
        mounts
            .iter()
            .all(|mount| !mount.source.display().to_string().contains("srt-projection-")),
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
```

**Step 2: Run the test and verify RED**

Run:

```bash
cargo test sandbox::linux::filesystem::tests::test_filtered_alias_bind_does_not_create_copy_projection -- --nocapture
```

Expected: FAIL because current code creates an `srt-projection-*` copy projection.

**Step 3: Add failing fastfail tests**

Add tests for:

```rust
#[test]
fn test_filtered_alias_rejects_asymmetric_read_and_list_globs() {
    let temp = tempfile::tempdir().unwrap();
    let source_root = temp.path().join("skill");
    std::fs::create_dir_all(&source_root).unwrap();

    let config = FilesystemConfig {
        binds: vec![crate::config::FilesystemBindConfig {
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
        err.to_string().contains("Linux read/list glob filtering requires identical denyReadGlobs and denyListGlobs"),
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
        err.to_string().contains("Linux read/list glob filtering is only supported for filesystem.binds aliases"),
        "{err}"
    );
}
```

**Step 4: Run the fastfail tests and verify RED**

Run:

```bash
cargo test sandbox::linux::filesystem::tests::test_filtered_alias_rejects_asymmetric_read_and_list_globs -- --nocapture
cargo test sandbox::linux::filesystem::tests::test_filtered_alias_rejects_non_alias_globs -- --nocapture
```

Expected: at least one test fails because current code warns/ignores or uses projection instead of fastfail.

## Task 2: Introduce Explicit Linux Mount Operations

**Files:**
- Modify: `/Users/wanglei/Projects/github-flaboy/sandbox-runtime-rs/src/sandbox/linux/filesystem.rs`
- Modify: `/Users/wanglei/Projects/github-flaboy/sandbox-runtime-rs/src/sandbox/linux/bwrap.rs`

**Step 1: Replace implicit boolean mount behavior**

Refactor `BindMount` to use an explicit operation enum:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindMountOp {
    ReadOnlyBind,
    WritableBind,
    DevNullBind,
    Tmpfs,
}

#[derive(Debug, Clone)]
pub struct BindMount {
    pub source: PathBuf,
    pub target: PathBuf,
    pub op: BindMountOp,
    pub cleanup_source: bool,
    pub create_target_dir: bool,
}
```

Keep compatibility constructors:

```rust
pub fn readonly(path: impl Into<PathBuf>) -> Self
pub fn writable(path: impl Into<PathBuf>) -> Self
pub fn block(path: impl Into<PathBuf>) -> Self
pub fn alias(source: impl Into<PathBuf>, target: impl Into<PathBuf>, writable: bool) -> Self
```

Add constructors:

```rust
pub fn filtered_alias_root(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self
pub fn filtered_alias_file(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self
pub fn hide_source_tmpfs(target: impl Into<PathBuf>) -> Self
```

**Step 2: Update bwrap arg generation**

Update `to_bwrap_args_with_created_dirs()`:

```rust
match self.op {
    BindMountOp::ReadOnlyBind => ["--ro-bind", source, target],
    BindMountOp::WritableBind => ["--bind", source, target],
    BindMountOp::DevNullBind => ["--ro-bind", "/dev/null", target],
    BindMountOp::Tmpfs => ["--tmpfs", target],
}
```

**Step 3: Preserve mount ordering**

In `generate_bwrap_command()`, replace the current readonly boolean split with:

1. writable bind mounts,
2. read-only root and filtered alias root mounts,
3. filtered alias file mounts,
4. deny/dev-null/tmpfs override mounts.

If keeping one `Vec<BindMount>` is simpler, preserve the generated order and sort only writable mounts before read-only mounts. Do not allow filtered file binds before their filtered root.

**Step 4: Run existing tests**

Run:

```bash
cargo test sandbox::linux::filesystem::tests::test_bind_mount_to_bwrap_args -- --nocapture
cargo test sandbox::linux::bwrap::tests::test_generate_bwrap_command_mounts_dev_after_readonly_root -- --nocapture
```

Expected: PASS after updating expectations to explicit `BindMountOp`.

## Task 3: Implement Filtered Alias Skeleton Generation

**Files:**
- Modify: `/Users/wanglei/Projects/github-flaboy/sandbox-runtime-rs/src/sandbox/linux/filesystem.rs`

**Step 1: Add filtered alias data structure**

Add:

```rust
#[derive(Debug)]
struct FilteredAliasPlan {
    skeleton_root: PathBuf,
    file_mounts: Vec<BindMount>,
}
```

**Step 2: Add skeleton builder**

Implement:

```rust
fn create_filtered_alias_plan(
    source_root: &Path,
    target_root: &Path,
    denied_patterns: &[glob::Pattern],
) -> Result<FilteredAliasPlan, SandboxError>
```

Required behavior:

- Create temp directory named `srt-filtered-alias-<pid>-<id>`.
- Traverse `source_root` recursively.
- If path matches any denied pattern, skip it.
- If entry is a directory, create the same relative directory in the skeleton and copy permissions.
- If entry is a regular file, create an empty placeholder file in the skeleton, copy permissions, and push `BindMount::filtered_alias_file(source_path, target_root.join(relative))`.
- If entry is a symlink, return `SandboxError::ExecutionFailed("Filtered filesystem bind does not support symlinks: ...")`.
- Do not call `fs::copy()`.

**Step 3: Replace alias projection path**

In `generate_alias_bind_mounts()`:

- If no translated patterns: keep direct alias bind.
- If translated patterns exist and alias is writable: fastfail.
- If translated patterns exist and alias is read-only:
  - call `create_filtered_alias_plan()`;
  - push `BindMount::filtered_alias_root(plan.skeleton_root, alias.target)`;
  - append `plan.file_mounts`;
  - hide the original source with `BindMount::hide_source_tmpfs(alias.source)`.

**Step 4: Remove copy projection path**

Delete these Linux projection helpers after tests cover the replacement:

- `generate_projection_mounts()`
- `glob_projection_root()`
- `create_projection_root()`
- `create_empty_projection_root()`
- `copy_projection_tree()`
- `BindMount::projected_alias()`
- `BindMount::projection()`
- `BindMount::hide_source()` if replaced by tmpfs hiding.

Do not keep dead code as a fallback.

**Step 5: Run RED tests and verify GREEN**

Run:

```bash
cargo test sandbox::linux::filesystem::tests::test_filtered_alias_bind_does_not_create_copy_projection -- --nocapture
cargo test sandbox::linux::filesystem::tests::test_filtered_alias_rejects_asymmetric_read_and_list_globs -- --nocapture
cargo test sandbox::linux::filesystem::tests::test_filtered_alias_rejects_non_alias_globs -- --nocapture
```

Expected: PASS.

## Task 4: Add Fastfail Validation for Linux Glob Policy

**Files:**
- Modify: `/Users/wanglei/Projects/github-flaboy/sandbox-runtime-rs/src/sandbox/linux/filesystem.rs`

**Step 1: Add validation helper**

Add:

```rust
fn validate_linux_glob_filter_contract(
    config: &FilesystemConfig,
    aliases: &[AliasBind],
) -> Result<(), SandboxError>
```

Required checks:

- normalized `deny_read_globs` equals normalized `deny_list_globs`;
- every normalized glob targets exactly one alias target;
- no glob targets a writable alias;
- no Linux glob filtering exists without aliases.

**Step 2: Fail on ignored Linux write globs**

In `generate_bind_mounts()`:

- replace current warning for glob `allow_write` with `SandboxError::ExecutionFailed("Linux allowWrite glob patterns are not supported: ...")`;
- replace current warning for glob `deny_write` with `SandboxError::ExecutionFailed("Linux denyWrite glob patterns are not supported: ...")`.

**Step 3: Add tests**

Add:

```rust
#[test]
fn test_linux_allow_write_glob_fastfails() { ... }

#[test]
fn test_linux_deny_write_glob_fastfails() { ... }

#[test]
fn test_filtered_alias_rejects_writable_alias() { ... }
```

**Step 4: Run tests**

Run:

```bash
cargo test sandbox::linux::filesystem::tests::test_linux_allow_write_glob_fastfails -- --nocapture
cargo test sandbox::linux::filesystem::tests::test_linux_deny_write_glob_fastfails -- --nocapture
cargo test sandbox::linux::filesystem::tests::test_filtered_alias_rejects_writable_alias -- --nocapture
```

Expected: PASS.

## Task 5: Add Linux Integration Tests for Read and List Semantics

**Files:**
- Modify: `/Users/wanglei/Projects/github-flaboy/sandbox-runtime-rs/tests/cli_integration.rs`

**Step 1: Add Linux-only integration test**

Add:

```rust
#[cfg(target_os = "linux")]
#[test]
fn linux_filtered_alias_hides_denied_markdown_from_read_and_list() {
    let temp = tempfile::tempdir().unwrap();
    let source_root = temp.path().join("skill-source");
    std::fs::create_dir_all(source_root.join("scripts")).unwrap();
    std::fs::write(source_root.join("SKILL.md"), "hidden").unwrap();
    std::fs::write(source_root.join("scripts").join("run.sh"), "#!/bin/sh\necho allowed").unwrap();

    let settings = temp.path().join("settings.json");
    std::fs::write(
        &settings,
        serde_json::json!({
            "network": { "allowAllUnixSockets": true },
            "filesystem": {
                "binds": [{
                    "source": source_root,
                    "target": "/skills/triage",
                    "writable": false
                }],
                "denyReadGlobs": ["/skills/triage/**/*.md"],
                "denyListGlobs": ["/skills/triage/**/*.md"]
            }
        })
        .to_string(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_srt"))
        .args([
            "-s",
            settings.to_str().unwrap(),
            "-c",
            "test ! -e /skills/triage/SKILL.md && ! ls /skills/triage | grep SKILL.md && test -f /skills/triage/scripts/run.sh && cat /skills/triage/scripts/run.sh",
        ])
        .output()
        .expect("srt should execute");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
```

Adjust JSON serialization if `PathBuf` direct serialization does not produce the desired string.

**Step 2: Run locally where possible**

On macOS this test is cfg-gated and will not run. Still run:

```bash
cargo test --test cli_integration
```

Expected locally: existing tests pass; Linux-only test is skipped on macOS.

## Task 6: Run Full Local Static Verification

**Files:**
- No code changes.

**Step 1: Format**

Run:

```bash
cargo fmt --check
```

Expected: PASS.

**Step 2: Unit and integration tests**

Run:

```bash
cargo test
```

Expected: PASS for locally compiled target.

**Step 3: Clippy**

Run:

```bash
cargo clippy --all-targets -- -D warnings
```

Expected: PASS.

## Task 7: Verify in AWS `syngy-sgp` Linux Kubernetes

**Files:**
- No repo files changed by this task.

**Step 1: Confirm cluster**

Run:

```bash
export KUBECTL=/Users/wanglei/Library/bin/kubectl
export KUBECONFIG=/Users/wanglei/.kube/config.d/syngy-sgp.yaml
$KUBECTL config current-context
$KUBECTL get nodes -o wide
```

Expected:

- context is `syngy-sgp`;
- node is Ready;
- kernel is `6.12.80-106.156.amzn2023.x86_64` or newer.

**Step 2: Start a disposable Linux build pod**

Run:

```bash
export POD=srt-linux-filtered-bind-test
$KUBECTL run "$POD" \
  --namespace default \
  --image=rust:1-bookworm \
  --restart=Never \
  --command -- sleep 3600
$KUBECTL wait --namespace default --for=condition=Ready "pod/$POD" --timeout=180s
```

Expected: pod is Ready.

**Step 3: Install Linux runtime dependencies inside pod**

Run:

```bash
$KUBECTL exec --namespace default "$POD" -- bash -lc 'apt-get update && apt-get install -y bubblewrap socat ripgrep'
$KUBECTL exec --namespace default "$POD" -- bash -lc 'bwrap --version && socat -V >/dev/null && rg --version | head -1 && uname -a'
```

Expected: dependencies are present.

**Step 4: Copy source into pod without local `target`**

Run from `/Users/wanglei/Projects/github-flaboy/sandbox-runtime-rs`:

```bash
$KUBECTL exec --namespace default "$POD" -- bash -lc 'mkdir -p /work/sandbox-runtime-rs'
tar --exclude='./target' --exclude='./.git' -cf - . \
  | $KUBECTL exec --namespace default -i "$POD" -- tar -xf - -C /work/sandbox-runtime-rs
```

Expected: source exists at `/work/sandbox-runtime-rs`.

**Step 5: Run Linux tests**

Run:

```bash
$KUBECTL exec --namespace default "$POD" -- bash -lc 'cd /work/sandbox-runtime-rs && cargo test'
$KUBECTL exec --namespace default "$POD" -- bash -lc 'cd /work/sandbox-runtime-rs && cargo clippy --all-targets -- -D warnings'
```

Expected: PASS.

**Step 6: Run behavioral shell verification**

Run:

```bash
$KUBECTL exec --namespace default "$POD" -- bash -lc '
set -euo pipefail
cd /work/sandbox-runtime-rs
cargo build --release
rm -rf /tmp/srt-skill-src /tmp/srt-projection-* /tmp/srt-filtered-alias-*
mkdir -p /tmp/srt-skill-src/triage/scripts /tmp/srt-skill-src/triage/references
printf "hidden skill doc\n" > /tmp/srt-skill-src/triage/SKILL.md
printf "hidden reference\n" > /tmp/srt-skill-src/triage/references/policy.md
printf "#!/bin/sh\necho allowed\n" > /tmp/srt-skill-src/triage/scripts/run.sh
chmod +x /tmp/srt-skill-src/triage/scripts/run.sh
cat > /tmp/srt-settings.json <<JSON
{
  "network": { "allowAllUnixSockets": true },
  "filesystem": {
    "binds": [{
      "source": "/tmp/srt-skill-src/triage",
      "target": "/skills/triage",
      "writable": false
    }],
    "denyReadGlobs": ["/skills/triage/**/*.md"],
    "denyListGlobs": ["/skills/triage/**/*.md"]
  }
}
JSON
SRT_DEBUG=1 target/release/srt -s /tmp/srt-settings.json -c "
  test ! -e /skills/triage/SKILL.md &&
  test ! -e /skills/triage/references/policy.md &&
  ! ls /skills/triage | grep SKILL.md &&
  ! ls /skills/triage/references | grep policy.md &&
  /skills/triage/scripts/run.sh
"
test ! -e /tmp/srt-projection-*
'
```

Expected:

- command exits 0;
- stdout contains `allowed`;
- denied markdown files do not exist in sandbox;
- denied markdown files are absent from directory listings;
- no `/tmp/srt-projection-*` path is created.

**Step 7: Run performance smoke verification**

Run:

```bash
$KUBECTL exec --namespace default "$POD" -- bash -lc '
set -euo pipefail
cd /work/sandbox-runtime-rs
rm -rf /tmp/srt-skill-src /tmp/srt-projection-* /tmp/srt-filtered-alias-*
for i in 1 2 3 4; do
  mkdir -p /tmp/srt-skill-src/skill$i/scripts /tmp/srt-skill-src/skill$i/references
  for n in $(seq 1 200); do
    printf "allowed $i $n\n" > /tmp/srt-skill-src/skill$i/scripts/file$n.txt
    printf "hidden $i $n\n" > /tmp/srt-skill-src/skill$i/references/file$n.md
  done
done
cat > /tmp/srt-settings-many.json <<JSON
{
  "network": { "allowAllUnixSockets": true },
  "filesystem": {
    "binds": [
      { "source": "/tmp/srt-skill-src/skill1", "target": "/skills/skill1", "writable": false },
      { "source": "/tmp/srt-skill-src/skill2", "target": "/skills/skill2", "writable": false },
      { "source": "/tmp/srt-skill-src/skill3", "target": "/skills/skill3", "writable": false },
      { "source": "/tmp/srt-skill-src/skill4", "target": "/skills/skill4", "writable": false }
    ],
    "denyReadGlobs": ["/skills/skill1/**/*.md", "/skills/skill2/**/*.md", "/skills/skill3/**/*.md", "/skills/skill4/**/*.md"],
    "denyListGlobs": ["/skills/skill1/**/*.md", "/skills/skill2/**/*.md", "/skills/skill3/**/*.md", "/skills/skill4/**/*.md"]
  }
}
JSON
/usr/bin/time -f "elapsed=%e" target/release/srt -s /tmp/srt-settings-many.json -c "
  test -f /skills/skill1/scripts/file200.txt &&
  test ! -e /skills/skill1/references/file200.md &&
  test -f /skills/skill4/scripts/file200.txt &&
  test ! -e /skills/skill4/references/file200.md
"
test ! -e /tmp/srt-projection-*
'
```

Expected:

- command exits 0;
- no projection copy directory exists;
- elapsed time is recorded for comparison against the RCA baseline.

Observed in AWS `syngy-sgp` privileged Linux pod:

- command exited 0;
- denied markdown paths were absent from read and list views;
- no `/tmp/srt-projection-*` directory existed;
- 4 aliases with 800 generated files completed in `elapsed=3.48`.

**Step 8: Cleanup disposable pod**

Run:

```bash
$KUBECTL delete pod --namespace default "$POD" --wait=true
```

Expected: pod is deleted.

## Task 8: Update Documentation

**Files:**
- Modify: `/Users/wanglei/Projects/github-flaboy/sandbox-runtime-rs/README.md`
- Modify: `/Users/wanglei/Projects/github-flaboy/sandbox-runtime-rs/CLAUDE.md`

**Step 1: Update Linux filesystem docs**

Document:

- Linux read/list glob filtering is supported only for read-only `filesystem.binds` aliases.
- `denyReadGlobs` and `denyListGlobs` must match exactly on Linux.
- Unsupported glob shapes fail before execution.
- Linux no longer copies projection trees for filtered aliases.

**Step 2: Run doc-adjacent verification**

Run:

```bash
cargo test
```

Expected: PASS.

## Task 9: Final Review Checklist

**Files:**
- Review all modified files.

Checklist:

- [x] No call site remains for `copy_projection_tree()`.
- [x] No Linux `srt-projection-*` directory is created for alias glob filtering.
- [x] Denied markdown files are unreadable and absent from `ls`.
- [x] Allowed non-markdown files retain content through read-only bind mounts.
- [x] Unsupported glob policies fail before bwrap execution.
- [x] No warning-and-ignore behavior remains for Linux filesystem glob policy touched by this change.
- [x] AWS `syngy-sgp` Linux test commands passed.
- [x] Existing macOS code path is unchanged except shared config docs/tests.
- [x] Existing unrelated local modifications were not reverted.

## Task 10: Commit

**Files:**
- Stage only files modified for this plan.

**Step 1: Inspect status**

Run:

```bash
git status --short
git diff -- src/sandbox/linux/filesystem.rs src/sandbox/linux/bwrap.rs tests/cli_integration.rs README.md CLAUDE.md docs/plans/2026-05-21-srt-linux-filtered-bind-sandbox.md
```

Expected: diff contains only this planned change and pre-existing unrelated changes are not staged.

**Step 2: Commit**

Run:

```bash
git add src/sandbox/linux/filesystem.rs src/sandbox/linux/bwrap.rs tests/cli_integration.rs README.md CLAUDE.md docs/plans/2026-05-21-srt-linux-filtered-bind-sandbox.md
git commit -m "fix: replace linux skill projections with filtered binds"
```

Expected: commit succeeds.
