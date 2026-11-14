//! `spiceio --check-auth`: resolves the S3 auth configuration exactly as
//! startup does and exits without connecting to anything. `make install`
//! relies on it to refuse an agent configuration that would stop the agent
//! from starting, so its verdict must match startup's.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const AUTH_VARS: [&str; 4] = [
    "SPICEIO_S3_AUTH",
    "SPICEIO_S3_ACCESS_KEY_ID",
    "SPICEIO_S3_SECRET_ACCESS_KEY",
    "SPICEIO_S3_CREDENTIALS_FILE",
];

/// Run `--check-auth` with exactly `vars` set among the auth variables, and
/// no SMB settings at all: it must not need them.
fn check_auth(vars: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_spiceio"));
    cmd.arg("--check-auth");
    for name in AUTH_VARS {
        cmd.env_remove(name);
    }
    for name in [
        "SPICEIO_SMB_SERVER",
        "SPICEIO_SMB_USER",
        "SPICEIO_SMB_PASS",
        "SPICEIO_SMB_SHARE",
        "SPICEIO_LOG_FILE",
    ] {
        cmd.env_remove(name);
    }
    cmd.envs(vars.iter().copied());
    cmd.output().expect("failed to spawn spiceio")
}

fn keys_file(tag: &str, contents: &str, mode: u32) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "spiceio-check-auth-{tag}-{}.keys",
        std::process::id()
    ));
    std::fs::write(&path, contents).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn path_str(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn no_keys_is_off() {
    let out = check_auth(&[]);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "S3 auth: off (requests are not authenticated)\n"
    );
}

#[test]
fn credentials_file_defaults_to_enforce_and_lists_key_ids() {
    let keys = keys_file(
        "enforce",
        "# rotation\nold-key 0123456789abcdef0123\nnew-key fedcba9876543210fedc\n",
        0o600,
    );
    let out = check_auth(&[("SPICEIO_S3_CREDENTIALS_FILE", path_str(&keys))]);
    let _ = std::fs::remove_file(&keys);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "S3 auth: enforce (SigV4; access keys: new-key, old-key)\n"
    );
}

#[test]
fn explicit_log_mode_is_reported() {
    let keys = keys_file("log", "k 0123456789abcdef0123\n", 0o600);
    let out = check_auth(&[
        ("SPICEIO_S3_CREDENTIALS_FILE", path_str(&keys)),
        ("SPICEIO_S3_AUTH", "log"),
    ]);
    let _ = std::fs::remove_file(&keys);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "S3 auth: log (SigV4; access keys: k)\n");
}

#[test]
fn secrets_are_never_printed() {
    let secret = "do-not-print-this-secret";
    let out = check_auth(&[
        ("SPICEIO_S3_ACCESS_KEY_ID", "inline"),
        ("SPICEIO_S3_SECRET_ACCESS_KEY", secret),
    ]);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert!(!text(&out.stdout).contains(secret));
    assert!(!text(&out.stderr).contains(secret));
}

#[test]
fn group_readable_credentials_file_fails() {
    let keys = keys_file("mode", "k 0123456789abcdef0123\n", 0o644);
    let out = check_auth(&[("SPICEIO_S3_CREDENTIALS_FILE", path_str(&keys))]);
    let _ = std::fs::remove_file(&keys);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(
        text(&out.stderr).contains("chmod 600"),
        "stderr: {}",
        text(&out.stderr)
    );
}

#[test]
fn enforce_without_a_key_fails() {
    let out = check_auth(&[("SPICEIO_S3_AUTH", "enforce")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("needs at least one access key"),
        "stderr: {}",
        text(&out.stderr)
    );
}

#[test]
fn short_secret_fails() {
    let keys = keys_file("short", "k short\n", 0o600);
    let out = check_auth(&[("SPICEIO_S3_CREDENTIALS_FILE", path_str(&keys))]);
    let _ = std::fs::remove_file(&keys);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("at least 16 are required"),
        "stderr: {}",
        text(&out.stderr)
    );
}
