//! Where spiceio's SMB password comes from, and the commands that manage it.
//!
//! The password is taken from exactly one of:
//!
//! - `SPICEIO_SMB_PASS`: the password itself (the historical way).
//! - `SPICEIO_SMB_PASS_KEYCHAIN`: the *service* of a generic-password item in
//!   the macOS keychain (the login keychain, or the keychain file named by
//!   `SPICEIO_SMB_PASS_KEYCHAIN_PATH`). See [`crate::keychain`] for what that
//!   protects against and what it does not.
//!
//! Setting both is a configuration error: which one wins would be a guess.
//!
//! The item's *account* is not configured; it is derived from the SMB
//! settings as `smb://[domain;]user@server[:port]` ([`account`]). That binds
//! the stored password to the server it is meant for. Any process running as
//! the same user can edit a launchd plist; if the item were found by service
//! alone, pointing `SPICEIO_SMB_SERVER` at a host that process controls would
//! make spiceio run NTLMv2 against it with the real password, handing over a
//! response that can be cracked offline. With the server in the key, a
//! changed server finds no item and nothing is sent.
//!
//! `spiceio --store-smb-password` creates or updates the item (reading the
//! password from the terminal without echo, or from standard input), and
//! `spiceio --check-smb-password` resolves it exactly as startup would.
//! Neither ever prints the password.

use std::ffi::{CString, c_char};
use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use crate::keychain::{self, Item};

/// The keychain service `--store-smb-password` and `make install` use when
/// `SPICEIO_SMB_PASS_KEYCHAIN` does not name one.
pub const DEFAULT_SERVICE: &str = "ai.spice.spiceio.smb";

/// SMB's port; [`account`] leaves it out, as an `smb://` URL would.
pub const DEFAULT_PORT: u16 = 445;

/// What the password is for: everything that decides where it is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// `SPICEIO_SMB_SERVER`.
    pub server: String,
    /// `SPICEIO_SMB_PORT`.
    pub port: u16,
    /// `SPICEIO_SMB_USER`.
    pub user: String,
    /// `SPICEIO_SMB_DOMAIN` (may be empty).
    pub domain: String,
}

/// The keychain account a password for `dest` is stored under:
/// `smb://[domain;]user@server[:port]`, with an IPv6 literal bracketed and
/// the port only when it is not 445. It is a lookup key, never parsed back.
pub fn account(dest: &Destination) -> String {
    let mut s = String::from("smb://");
    if !dest.domain.is_empty() {
        s.push_str(&dest.domain);
        s.push(';');
    }
    s.push_str(&dest.user);
    s.push('@');
    if dest.server.contains(':') && !dest.server.starts_with('[') {
        s.push('[');
        s.push_str(&dest.server);
        s.push(']');
    } else {
        s.push_str(&dest.server);
    }
    if dest.port != DEFAULT_PORT {
        s.push(':');
        s.push_str(&dest.port.to_string());
    }
    s
}

/// The password settings, read from the environment (or any lookup, for
/// tests). Empty values count as unset, as they do for every other
/// `SPICEIO_SMB_*` variable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// `SPICEIO_SMB_SERVER`.
    pub server: Option<String>,
    /// `SPICEIO_SMB_PORT`, parsed.
    pub port: u16,
    /// `SPICEIO_SMB_USER`.
    pub user: Option<String>,
    /// `SPICEIO_SMB_DOMAIN`.
    pub domain: String,
    /// `SPICEIO_SMB_PASS`.
    pub inline: Option<String>,
    /// `SPICEIO_SMB_PASS_KEYCHAIN`.
    pub service: Option<String>,
    /// `SPICEIO_SMB_PASS_KEYCHAIN_PATH`.
    pub keychain_path: Option<PathBuf>,
}

impl Settings {
    /// Read the settings through `get` (`std::env::var` in production).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let get = |name: &str| get(name).filter(|v| !v.is_empty());
        let port = match get("SPICEIO_SMB_PORT") {
            None => DEFAULT_PORT,
            Some(raw) => raw
                .trim()
                .parse()
                .map_err(|_| format!("SPICEIO_SMB_PORT={raw} is not a valid port"))?,
        };
        Ok(Self {
            server: get("SPICEIO_SMB_SERVER"),
            port,
            user: get("SPICEIO_SMB_USER"),
            domain: get("SPICEIO_SMB_DOMAIN").unwrap_or_default(),
            inline: get("SPICEIO_SMB_PASS"),
            service: get("SPICEIO_SMB_PASS_KEYCHAIN"),
            keychain_path: get("SPICEIO_SMB_PASS_KEYCHAIN_PATH").map(PathBuf::from),
        })
    }

    /// Read the settings from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// The destination, which a keychain lookup needs in full.
    pub fn destination(&self) -> Result<Destination, String> {
        match (&self.server, &self.user) {
            (Some(server), Some(user)) => Ok(Destination {
                server: server.clone(),
                port: self.port,
                user: user.clone(),
                domain: self.domain.clone(),
            }),
            _ => Err(
                "SPICEIO_SMB_SERVER and SPICEIO_SMB_USER are required: the keychain item is \
                 keyed on them"
                    .into(),
            ),
        }
    }

    /// The keychain item for `service` and these settings' destination.
    pub fn item(&self, service: &str) -> Result<Item, String> {
        let dest = self.destination()?;
        if let Some(path) = &self.keychain_path
            && !path.is_absolute()
        {
            return Err(format!(
                "SPICEIO_SMB_PASS_KEYCHAIN_PATH={} is not an absolute path",
                path.display()
            ));
        }
        Ok(Item {
            service: service.to_string(),
            account: account(&dest),
            keychain: self.keychain_path.clone(),
        })
    }
}

/// Where the password comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `SPICEIO_SMB_PASS`.
    Env(String),
    /// A keychain item.
    Keychain(Item),
}

impl Source {
    /// Decide the source from the settings, without reading the keychain.
    pub fn resolve(settings: &Settings) -> Result<Self, String> {
        match (&settings.inline, &settings.service) {
            (Some(_), Some(_)) => {
                Err("set one of SPICEIO_SMB_PASS and SPICEIO_SMB_PASS_KEYCHAIN, not both".into())
            }
            (Some(password), None) => Ok(Self::Env(password.clone())),
            (None, Some(service)) => Ok(Self::Keychain(settings.item(service)?)),
            (None, None) => Err(
                "SPICEIO_SMB_PASS or SPICEIO_SMB_PASS_KEYCHAIN is required (the password, or \
                 the keychain service it is stored under)"
                    .into(),
            ),
        }
    }

    /// One line for logs and `--check-smb-password`. Never the password.
    pub fn describe(&self) -> String {
        match self {
            Self::Env(_) => "SPICEIO_SMB_PASS (environment)".into(),
            Self::Keychain(item) => format!(
                "keychain item \"{}\" for {} ({})",
                item.service,
                item.account,
                item.location()
            ),
        }
    }

    /// The password, read from wherever it lives. Keychain failures come
    /// back as a sentence that says what to do about them.
    pub fn load(&self) -> Result<String, String> {
        match self {
            Self::Env(password) => Ok(password.clone()),
            Self::Keychain(item) => {
                let bytes = keychain::read(item).map_err(|e| explain(item, &e))?;
                let password = String::from_utf8(bytes).map_err(|_| {
                    format!(
                        "keychain item \"{}\" for {} is not UTF-8 text",
                        item.service, item.account
                    )
                })?;
                if password.is_empty() {
                    return Err(format!(
                        "keychain item \"{}\" for {} is empty",
                        item.service, item.account
                    ));
                }
                Ok(password)
            }
        }
    }
}

/// Single-quote `s` for a shell command line in a suggestion.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The `security delete-generic-password` command that removes `item`.
fn delete_command(item: &Item) -> String {
    let mut cmd = format!(
        "security delete-generic-password -s {} -a {}",
        sh_quote(&item.service),
        sh_quote(&item.account)
    );
    if let Some(path) = &item.keychain {
        cmd.push(' ');
        cmd.push_str(&sh_quote(&path.display().to_string()));
    }
    cmd
}

/// A keychain failure as a sentence that says what to do.
fn explain(item: &Item, e: &keychain::Error) -> String {
    let what = format!("keychain item \"{}\" for {}", item.service, item.account);
    match e {
        keychain::Error::NotFound => format!(
            "no {what} in {}. Store the password with `spiceio --store-smb-password`, run with \
             the same SPICEIO_SMB_* settings: the item is keyed on the server, user, domain and \
             port",
            item.location()
        ),
        keychain::Error::Denied { locked: true } => {
            let unlock = match &item.keychain {
                Some(path) => format!(
                    "security unlock-keychain {}",
                    sh_quote(&path.display().to_string())
                ),
                None => "security unlock-keychain".into(),
            };
            format!(
                "{} is locked, and spiceio never prompts for it. The login keychain unlocks \
                 when you log in to the Mac (a launchd agent in that session can read it); from \
                 a shell: {unlock}",
                item.location()
            )
        }
        keychain::Error::Denied { locked: false } => {
            let signature = keychain::own_signature()
                .map(|s| s.requirement)
                .unwrap_or_else(|_| "unknown".into());
            format!(
                "this spiceio binary may not read {what}: its signature ({signature}) is not on \
                 the item's access list, so a binary with another signature stored it. Install \
                 with `make install`, which signs with the same local identity every time, or \
                 delete the item ({}; macOS may ask for your login password) and run \
                 `spiceio --store-smb-password` again",
                delete_command(item)
            )
        }
        keychain::Error::NoSuchKeychain => format!(
            "{} does not exist (SPICEIO_SMB_PASS_KEYCHAIN_PATH)",
            item.location()
        ),
        other => format!("{what} in {}: {other}", item.location()),
    }
}

/// `spiceio --check-smb-password`: resolve the password the way startup
/// does, report where it came from, exit 0; or say why it cannot, exit 1.
/// Touches nothing else (no SMB, no listener, no log file).
pub fn check_command() -> i32 {
    let source = match Settings::from_env().and_then(|s| Source::resolve(&s)) {
        Ok(source) => source,
        Err(e) => {
            eprintln!("SMB password: {e}");
            return 1;
        }
    };
    match source.load() {
        Ok(_) => {
            println!("SMB password: {}", source.describe());
            0
        }
        Err(e) => {
            eprintln!("SMB password: {e}");
            1
        }
    }
}

/// `spiceio --store-smb-password`: store the SMB password for the
/// configured server and user in the keychain, then read it back.
///
/// The password comes from the terminal (asked twice, without echo) or, when
/// standard input is not a terminal, from all of standard input less one
/// trailing newline, so `plutil -extract … raw` can be piped in. It is never
/// taken from `SPICEIO_SMB_PASS`: a password in the environment is what this
/// replaces, and taking it from there would invite putting it on a command
/// line.
pub fn store_command() -> i32 {
    match store() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("spiceio --store-smb-password: {e}");
            1
        }
    }
}

fn store() -> Result<(), String> {
    let settings = Settings::from_env()?;
    if settings.inline.is_some() {
        return Err(
            "SPICEIO_SMB_PASS is set. This command reads the password from the terminal or \
             standard input, never from the environment; unset it"
                .into(),
        );
    }
    let service = settings.service.as_deref().unwrap_or(DEFAULT_SERVICE);
    let item = settings.item(service)?;
    let signature = keychain::own_signature().map_err(|e| format!("code signature: {e}"))?;
    if signature.adhoc {
        eprintln!(
            "warning: this spiceio binary is ad-hoc signed ({}). The keychain item will be \
             readable by this exact build only; every rebuild is a different signature. Store \
             it with a binary `make install` signed instead.",
            signature.requirement
        );
    }
    let mut password = read_password(&item.account)?;
    let label = format!("spiceio SMB password ({})", item.account);
    let result = keychain::store(&item, &label, &password);
    wipe(&mut password);
    let stored = result.map_err(|e| match e {
        keychain::Error::Denied { locked: false } => format!(
            "keychain item \"{service}\" for {account} exists but this binary cannot read it, \
             so it was left alone: its signature ({sig}) is not on the item's access list. To \
             replace it, delete it first ({cmd}; macOS may ask for your login password), then run \
             this again",
            service = item.service,
            account = item.account,
            sig = signature.requirement,
            cmd = delete_command(&item),
        ),
        other => explain(&item, &other),
    })?;
    println!(
        "SMB password for {}: {stored} in keychain item \"{}\" ({})",
        item.account,
        item.service,
        item.location()
    );
    println!("readable by: {}", signature.requirement);
    if settings.service.is_none() {
        println!(
            "spiceio reads it with SPICEIO_SMB_PASS_KEYCHAIN={service} (and SPICEIO_SMB_PASS unset)"
        );
    }
    Ok(())
}

/// Overwrite a buffer that held a secret before it is freed. Best effort:
/// copies made by the keychain or the allocator are out of reach.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn read_password(account: &str) -> Result<Vec<u8>, String> {
    let password = if std::io::stdin().is_terminal() {
        let mut first = prompt(&format!("SMB password for {account}: "))?;
        let mut second = prompt("Retype the password: ")?;
        let same = first == second;
        wipe(&mut second);
        if !same {
            wipe(&mut first);
            return Err("the two entries differ".into());
        }
        first
    } else {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("reading standard input: {e}"))?;
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        buf
    };
    if password.is_empty() {
        return Err("empty password".into());
    }
    if std::str::from_utf8(&password).is_err() {
        return Err("the password is not UTF-8 text".into());
    }
    Ok(password)
}

const RPP_REQUIRE_TTY: i32 = 0x02;
/// Longest password `prompt` accepts; one byte of the buffer is the NUL.
const PROMPT_MAX: usize = 1023;

unsafe extern "C" {
    fn readpassphrase(
        prompt: *const c_char,
        buf: *mut c_char,
        bufsiz: usize,
        flags: i32,
    ) -> *mut c_char;
}

/// Read one line from the controlling terminal with echo off.
/// `readpassphrase(3)` restores the terminal if a signal interrupts it.
fn prompt(text: &str) -> Result<Vec<u8>, String> {
    let c_prompt = CString::new(text).map_err(|_| "prompt contains NUL".to_string())?;
    let mut buf = vec![0u8; PROMPT_MAX + 1];
    // SAFETY: `buf` is writable for `buf.len()` bytes and `c_prompt` is
    // NUL-terminated; readpassphrase NUL-terminates within the buffer.
    let ok = unsafe {
        readpassphrase(
            c_prompt.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            RPP_REQUIRE_TTY,
        )
    };
    if ok.is_null() {
        wipe(&mut buf);
        return Err("could not read the password from the terminal".into());
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    if len >= PROMPT_MAX {
        wipe(&mut buf);
        return Err(format!(
            "passwords longer than {} bytes are not supported",
            PROMPT_MAX - 1
        ));
    }
    let out = buf[..len].to_vec();
    wipe(&mut buf);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn dest(server: &str, port: u16, user: &str, domain: &str) -> Destination {
        Destination {
            server: server.into(),
            port,
            user: user.into(),
            domain: domain.into(),
        }
    }

    fn settings(vars: &[(&str, &str)]) -> Result<Settings, String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Settings::from_lookup(|name| map.get(name).cloned())
    }

    #[test]
    fn account_binds_server_user_domain_and_port() {
        assert_eq!(
            account(&dest("nas.local", 445, "alice", "")),
            "smb://alice@nas.local"
        );
        assert_eq!(
            account(&dest("nas.local", 4455, "alice", "CORP")),
            "smb://CORP;alice@nas.local:4455"
        );
        assert_eq!(
            account(&dest("fe80::1", 445, "alice", "")),
            "smb://alice@[fe80::1]"
        );
        assert_eq!(
            account(&dest("[fe80::1]", 445, "alice", "")),
            "smb://alice@[fe80::1]"
        );
        // A UPN user name keeps its @; the key is never parsed back.
        assert_eq!(
            account(&dest("10.0.0.5", 445, "alice@corp.example", "")),
            "smb://alice@corp.example@10.0.0.5"
        );
    }

    #[test]
    fn a_changed_server_is_a_different_item() {
        let base = [
            ("SPICEIO_SMB_SERVER", "nas.local"),
            ("SPICEIO_SMB_USER", "alice"),
            ("SPICEIO_SMB_PASS_KEYCHAIN", DEFAULT_SERVICE),
        ];
        let moved = [
            ("SPICEIO_SMB_SERVER", "attacker.example"),
            ("SPICEIO_SMB_USER", "alice"),
            ("SPICEIO_SMB_PASS_KEYCHAIN", DEFAULT_SERVICE),
        ];
        let a = Source::resolve(&settings(&base).unwrap()).unwrap();
        let b = Source::resolve(&settings(&moved).unwrap()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn inline_password_is_the_env_source() {
        let s = settings(&[("SPICEIO_SMB_PASS", "secret")]).unwrap();
        assert_eq!(Source::resolve(&s), Ok(Source::Env("secret".into())));
        assert_eq!(
            Source::resolve(&s).unwrap().describe(),
            "SPICEIO_SMB_PASS (environment)"
        );
    }

    #[test]
    fn keychain_source_names_service_account_and_keychain() {
        let s = settings(&[
            ("SPICEIO_SMB_SERVER", "nas"),
            ("SPICEIO_SMB_USER", "u"),
            ("SPICEIO_SMB_PASS_KEYCHAIN", "svc"),
            ("SPICEIO_SMB_PASS_KEYCHAIN_PATH", "/tmp/k.keychain-db"),
        ])
        .unwrap();
        let source = Source::resolve(&s).unwrap();
        assert_eq!(
            source,
            Source::Keychain(Item {
                service: "svc".into(),
                account: "smb://u@nas".into(),
                keychain: Some("/tmp/k.keychain-db".into()),
            })
        );
        assert_eq!(
            source.describe(),
            "keychain item \"svc\" for smb://u@nas (keychain /tmp/k.keychain-db)"
        );
    }

    #[test]
    fn both_or_neither_is_an_error() {
        let both = settings(&[
            ("SPICEIO_SMB_SERVER", "nas"),
            ("SPICEIO_SMB_USER", "u"),
            ("SPICEIO_SMB_PASS", "p"),
            ("SPICEIO_SMB_PASS_KEYCHAIN", "svc"),
        ])
        .unwrap();
        assert!(Source::resolve(&both).unwrap_err().contains("not both"));
        let neither =
            settings(&[("SPICEIO_SMB_SERVER", "nas"), ("SPICEIO_SMB_USER", "u")]).unwrap();
        assert!(
            Source::resolve(&neither)
                .unwrap_err()
                .contains("is required")
        );
    }

    #[test]
    fn empty_values_count_as_unset() {
        let s = settings(&[
            ("SPICEIO_SMB_PASS", ""),
            ("SPICEIO_SMB_PASS_KEYCHAIN", "svc"),
            ("SPICEIO_SMB_SERVER", "nas"),
            ("SPICEIO_SMB_USER", "u"),
            ("SPICEIO_SMB_PORT", ""),
        ])
        .unwrap();
        assert!(matches!(Source::resolve(&s), Ok(Source::Keychain(_))));
    }

    #[test]
    fn keychain_needs_server_and_user_and_an_absolute_path() {
        let s = settings(&[("SPICEIO_SMB_PASS_KEYCHAIN", "svc")]).unwrap();
        assert!(
            Source::resolve(&s)
                .unwrap_err()
                .contains("SPICEIO_SMB_SERVER")
        );
        let s = settings(&[
            ("SPICEIO_SMB_SERVER", "nas"),
            ("SPICEIO_SMB_USER", "u"),
            ("SPICEIO_SMB_PASS_KEYCHAIN", "svc"),
            ("SPICEIO_SMB_PASS_KEYCHAIN_PATH", "~/k.keychain-db"),
        ])
        .unwrap();
        assert!(
            Source::resolve(&s)
                .unwrap_err()
                .contains("not an absolute path")
        );
    }

    #[test]
    fn bad_port_is_an_error() {
        assert!(settings(&[("SPICEIO_SMB_PORT", "smb")]).is_err());
    }

    #[test]
    fn suggestions_quote_for_the_shell() {
        let item = Item {
            service: "svc".into(),
            account: "smb://CORP;o'neil@nas".into(),
            keychain: None,
        };
        assert_eq!(
            delete_command(&item),
            r"security delete-generic-password -s 'svc' -a 'smb://CORP;o'\''neil@nas'"
        );
    }
}
