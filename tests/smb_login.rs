//! The SMB login against a fake server (`scripts/fake-smb.py`), end to end
//! through the binary: a refused login is attempted once and never retried,
//! by `--check-smb-login` and by the server's startup loop alike, and a
//! "success" the server did not sign is not a login.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A running `scripts/fake-smb.py`, killed on drop.
struct Fake {
    child: Child,
    port: u16,
    log: PathBuf,
}

impl Fake {
    fn start(args: &[&str]) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let log = std::env::temp_dir().join(format!(
            "spiceio-fake-smb-{}-{}.log",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&log, "").unwrap();
        let mut child = Command::new("python3")
            .arg("-I")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fake-smb.py"))
            .args(args)
            .arg("--log")
            .arg(&log)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("python3");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port = line
            .trim()
            .strip_prefix("port ")
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("fake-smb.py did not report a port: {line:?}"));
        Self { child, port, log }
    }

    /// The log lines (`auth` per authenticating session setup, `tree` per
    /// tree connect it accepted).
    fn events(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.log);
    }
}

fn spiceio() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_spiceio"));
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", std::env::temp_dir())
        .env("SPICEIO_SMB_PASS", "not-the-password");
    cmd
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn check_login(fake: &Fake) -> Output {
    let port = fake.port.to_string();
    spiceio()
        .args([
            "--check-smb-login",
            "--server",
            "127.0.0.1",
            "--port",
            &port,
            "--user",
            "nobody",
            "--share",
            "share",
        ])
        .output()
        .unwrap()
}

#[test]
fn check_smb_login_tries_a_refused_login_once() {
    let fake = Fake::start(&[]);
    let out = check_login(&fake);
    let text = text(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("STATUS_LOGON_FAILURE"), "{text}");
    assert_eq!(fake.events(), ["auth"], "{text}");
}

#[test]
fn an_unsigned_success_is_not_a_login() {
    // The fake knows no password, so it cannot sign; the client must not
    // take its "success" as the server's.
    let fake = Fake::start(&["--accept"]);
    let out = check_login(&fake);
    let text = text(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(
        text.contains("did not prove it holds the session key"),
        "{text}"
    );
    assert_eq!(
        fake.events(),
        ["auth"],
        "the session was used anyway: {text}"
    );
}

#[test]
fn startup_stops_after_a_refused_login_and_says_why() {
    let fake = Fake::start(&[]);
    let http = TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = http.local_addr().unwrap();
    drop(http);
    let mut child = spiceio()
        .env("SPICEIO_SMB_SERVER", "127.0.0.1")
        .env("SPICEIO_SMB_PORT", fake.port.to_string())
        .env("SPICEIO_SMB_USER", "nobody")
        .env("SPICEIO_SMB_SHARE", "share")
        .env("SPICEIO_BIND", bind.to_string())
        .env("SPICEIO_SPILL_DIR", "off")
        .env("SPICEIO_WRITE_BACK", "0")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = mpsc::channel();
    let stderr = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut seen = Vec::new();
    while let Ok(line) = rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        let done = line.contains("SMB login refused");
        seen.push(line);
        if done {
            break;
        }
    }
    let log = seen.join("\n");
    assert!(log.contains("SMB login refused"), "{log}");

    // Longer than the connect backoff (2s) and the startup loop's (1s): a
    // retry would have landed by now.
    std::thread::sleep(Duration::from_secs(6));
    assert_eq!(fake.events(), ["auth"], "{log}");
    assert!(child.try_wait().unwrap().is_none(), "spiceio exited: {log}");

    let mut conn = TcpStream::connect(bind).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(b"GET /share/key HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    let _ = conn.read_to_string(&mut response);
    let _ = child.kill();
    let _ = child.wait();
    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    assert!(
        response.contains("cannot log in to the SMB backend")
            && response.contains("STATUS_LOGON_FAILURE"),
        "{response}"
    );
}
