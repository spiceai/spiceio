//! Startup reads the SMB password from `SPICEIO_SMB_PASS` or from the keychain
//! item `SPICEIO_SMB_PASS_KEYCHAIN` names, through the same resolution as
//! `--check-smb-password` (which test-codesign-local.sh covers end to end).
//! These run the server itself, against a throwaway keychain file, to show
//! startup takes that path: it logs where the password came from (never the
//! password), and a password it cannot get stops it with the reason instead
//! of leaving it retrying an SMB login that cannot succeed.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const SECRET: &str = "startup-test p@ss";

/// A throwaway keychain file, deleted on drop.
struct TempKeychain {
    dir: PathBuf,
    path: PathBuf,
}

impl TempKeychain {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("spiceio-startup-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("items.keychain-db");
        security(&["create-keychain", "-p", "pw", path.to_str().unwrap()]);
        security(&["set-keychain-settings", path.to_str().unwrap()]);
        Self { dir, path }
    }
}

impl Drop for TempKeychain {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/security")
            .args(["delete-keychain", self.path.to_str().unwrap()])
            .output();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn security(args: &[&str]) {
    let out = Command::new("/usr/bin/security")
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "security {args:?}");
}

/// spiceio with only the given SMB settings (plus a closed SMB port and an
/// ephemeral listener, so nothing real is contacted).
fn spiceio(keychain: Option<&Path>, vars: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_spiceio"));
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("SPICEIO_SMB_SERVER", "127.0.0.1")
        .env("SPICEIO_SMB_PORT", "9")
        .env("SPICEIO_SMB_USER", "startup")
        .env("SPICEIO_SMB_SHARE", "share")
        .env("SPICEIO_BIND", "127.0.0.1:0")
        .env("SPICEIO_SPILL_DIR", "off");
    if let Some(kc) = keychain {
        cmd.env("SPICEIO_SMB_PASS_KEYCHAIN_PATH", kc);
    }
    cmd.envs(vars.iter().copied());
    cmd
}

/// Read `child`'s stdout and stderr until a line contains `marker` (or
/// `timeout` passes), kill it, and return everything it printed.
fn read_until(child: &mut std::process::Child, marker: &str, timeout: Duration) -> String {
    let (tx, rx) = mpsc::channel();
    for stream in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
    }
    let mut seen = Vec::new();
    while let Ok(line) = rx.recv_timeout(timeout) {
        let done = line.contains(marker);
        seen.push(line);
        if done {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    while let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
        seen.push(line);
    }
    seen.join("\n")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn missing_keychain_item_stops_startup_with_the_reason() {
    let kc = TempKeychain::new("missing");
    let out = spiceio(
        Some(&kc.path),
        &[("SPICEIO_SMB_PASS_KEYCHAIN", "ai.spice.spiceio.smb")],
    )
    .output()
    .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains(
            "SMB password: no keychain item \"ai.spice.spiceio.smb\" for smb://****@127.0.0.1:9"
        ),
        "{}",
        text(&out)
    );
}

#[test]
fn both_sources_stop_startup() {
    let out = spiceio(
        None,
        &[
            ("SPICEIO_SMB_PASS", "x"),
            ("SPICEIO_SMB_PASS_KEYCHAIN", "ai.spice.spiceio.smb"),
        ],
    )
    .output()
    .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("not both"), "{}", text(&out));
}

#[test]
fn a_url_for_the_server_stops_startup_with_the_host_to_use() {
    let out = spiceio(None, &[("SPICEIO_SMB_PASS", "x")])
        .env("SPICEIO_SMB_SERVER", "smb://127.0.0.1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("SPICEIO_SMB_SERVER=smb://127.0.0.1 is a URL; expected a host name or IP address (use 127.0.0.1)"),
        "{}",
        text(&out)
    );
}

/// The password commands and startup parse SPICEIO_SMB_PORT with one
/// function, so an item stored for a padded port is found at startup.
#[test]
fn a_padded_port_finds_the_same_item_at_startup() {
    let kc = TempKeychain::new("padded-port");
    let vars = [
        ("SPICEIO_SMB_PASS_KEYCHAIN", "ai.spice.spiceio.smb"),
        ("SPICEIO_SMB_PORT", " 4455 "),
    ];
    let mut store = spiceio(Some(&kc.path), &vars)
        .arg("--store-smb-password")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    store
        .stdin
        .take()
        .unwrap()
        .write_all(SECRET.as_bytes())
        .unwrap();
    let out = store.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", text(&out));

    let mut child = spiceio(Some(&kc.path), &vars)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let log = read_until(&mut child, "connecting to smb://", Duration::from_secs(20));
    assert!(
        log.contains(
            "SMB password: keychain item \"ai.spice.spiceio.smb\" for smb://****@127.0.0.1:4455"
        ),
        "{log}"
    );
}

#[test]
fn neither_source_stops_startup() {
    let out = spiceio(None, &[]).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("SPICEIO_SMB_PASS or SPICEIO_SMB_PASS_KEYCHAIN is required"),
        "{}",
        text(&out)
    );
}

#[test]
fn stored_password_is_used_and_never_logged() {
    let kc = TempKeychain::new("stored");
    let service = [("SPICEIO_SMB_PASS_KEYCHAIN", "ai.spice.spiceio.smb")];

    // The test build is ad-hoc signed; storing with this same binary makes
    // its cdhash the item's access list, so this binary can read it back.
    let mut store = spiceio(Some(&kc.path), &service)
        .arg("--store-smb-password")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    store
        .stdin
        .take()
        .unwrap()
        .write_all(SECRET.as_bytes())
        .unwrap();
    let out = store.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", text(&out));

    let mut child = spiceio(Some(&kc.path), &service)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let log = read_until(&mut child, "connecting to smb://", Duration::from_secs(20));
    let found = log.contains("connecting to smb://");

    assert!(found, "startup never reached the SMB connect:\n{log}");
    assert!(
        log.contains(
            "SMB password: keychain item \"ai.spice.spiceio.smb\" for smb://****@127.0.0.1:9"
        ),
        "{log}"
    );
    assert!(
        !log.contains(SECRET),
        "the password reached the log:\n{log}"
    );
    assert!(
        !log.contains("startup@"),
        "the SMB user reached the log:\n{log}"
    );
}
