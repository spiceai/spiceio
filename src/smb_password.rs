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
//! `spiceio --check-smb-password` resolves it exactly as startup would. Both
//! take `--server`, `--user`, `--domain`, `--port` and `--service` on the
//! command line, each falling back to its environment variable. The password
//! is never taken from the command line: any process can read another's
//! arguments from the process list.
//!
//! Nothing here prints the password, or the SMB user name: output shows the
//! destination as `smb://****@server[:port]`, as the startup log always has.

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

/// The SMB port in `raw`, surrounding whitespace ignored.
fn parse_port(raw: &str) -> Option<u16> {
    raw.trim().parse().ok()
}

/// `value` with everything before its last `@` (user, and any password)
/// replaced by `****`, for messages. The last `@`, not the first or the one in
/// the authority, so a password holding `/` or `@` cannot survive either.
fn redact_userinfo(value: &str) -> String {
    let (scheme, rest) = match value.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, value),
    };
    let rest = match rest.rsplit_once('@') {
        Some((_, host)) => format!("****@{host}"),
        None => rest.to_string(),
    };
    match scheme {
        Some(scheme) => format!("{scheme}://{rest}"),
        None => rest,
    }
}

/// Check an SMB server setting (`what` names it in the error): a host name
/// or an IP address, nothing more. A URL (`smb://nas`), `user@host` or
/// `host:port` would otherwise be taken as a host name that never resolves,
/// and, as part of the keychain account, file the password under a server
/// that cannot exist. Errors never repeat user info: a mistyped server can
/// carry a password (`smb://alice:secret@nas`), and startup logs the error.
pub fn check_server(what: &str, value: &str) -> Result<(), String> {
    let shown = redact_userinfo(value);
    let hint = || {
        let rest = value.split_once("://").map_or(value, |(_, rest)| rest);
        let rest = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
        match rest.split(['/', '?', '#']).next().unwrap_or("") {
            "" => String::new(),
            host => format!(" (use {host})"),
        }
    };
    if value.contains("://") {
        return Err(format!(
            "{what}={shown} is a URL; expected a host name or IP address{}",
            hint()
        ));
    }
    if value.contains('@') {
        return Err(format!(
            "{what}={shown} includes a user name; expected a host name or IP address{} \
             (the user goes in SPICEIO_SMB_USER / --user)",
            hint()
        ));
    }
    if value.contains('/') || value.chars().any(char::is_whitespace) {
        return Err(format!(
            "{what}={shown:?}: expected a host name or IP address, nothing else"
        ));
    }
    // One colon followed by digits is host:port. An IPv6 literal has two or
    // more colons (or arrives bracketed).
    if let Some((host, port)) = value.split_once(':')
        && !port.contains(':')
        && !host.starts_with('[')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!(
            "{what}={value} includes a port; give the host ({host}) and the port separately \
             (SPICEIO_SMB_PORT / --port)"
        ));
    }
    Ok(())
}

/// `dest` for output: `smb://****@server[:port]`. The user name is masked, as
/// in the startup log's `connecting to smb://****@…` line; logs can travel
/// further than the terminal that typed the name.
pub fn shown(dest: &Destination) -> String {
    let mut s = String::from("smb://****@");
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

/// One setting's raw value and where it came from (`SPICEIO_SMB_SERVER`,
/// `--server`, …), so an error names what was actually set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// The value as given.
    pub value: String,
    /// The variable or flag it came from.
    pub from: &'static str,
}

/// The SMB settings that decide where the password comes from and which
/// keychain item holds it. Startup and the password commands both read them
/// through here, so they can never disagree about the item. Values are kept
/// raw and checked when used ([`Settings::destination`]), after any flags
/// have replaced them: an invalid environment value a flag overrides is not
/// an error. Empty values count as unset, and so does a port of only spaces
/// (a password of only spaces is still a password).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// `SPICEIO_SMB_SERVER` / `--server`.
    pub server: Option<Setting>,
    /// `SPICEIO_SMB_PORT` / `--port`.
    pub port: Option<Setting>,
    /// `SPICEIO_SMB_USER` / `--user`.
    pub user: Option<String>,
    /// `SPICEIO_SMB_DOMAIN` / `--domain`.
    pub domain: String,
    /// `SPICEIO_SMB_PASS`.
    pub inline: Option<String>,
    /// `SPICEIO_SMB_PASS_KEYCHAIN` / `--service`.
    pub service: Option<String>,
    /// `SPICEIO_SMB_PASS_KEYCHAIN_PATH`.
    pub keychain_path: Option<PathBuf>,
}

impl Settings {
    /// Read the settings through `get` (`std::env::var` in production).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let get = |name: &str| get(name).filter(|v| !v.is_empty());
        let setting = |name: &'static str| get(name).map(|value| Setting { value, from: name });
        Self {
            server: setting("SPICEIO_SMB_SERVER"),
            port: setting("SPICEIO_SMB_PORT").filter(|port| !port.value.trim().is_empty()),
            user: get("SPICEIO_SMB_USER"),
            domain: get("SPICEIO_SMB_DOMAIN").unwrap_or_default(),
            inline: get("SPICEIO_SMB_PASS"),
            service: get("SPICEIO_SMB_PASS_KEYCHAIN"),
            keychain_path: get("SPICEIO_SMB_PASS_KEYCHAIN_PATH").map(PathBuf::from),
        }
    }

    /// Read the settings from the process environment.
    pub fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Apply command-line flags over these settings: `--server`, `--user`,
    /// `--domain`, `--port` and `--service`, as `--flag value` or
    /// `--flag=value`. `subcommand` (the flag that chose the command) is
    /// skipped; anything else is an error, and a password flag is refused
    /// with the reason. Values are checked later, with the rest.
    pub fn with_args<I, S>(mut self, args: I, subcommand: &str) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut args = args.into_iter().map(|a| a.as_ref().to_string());
        let mut position = 0;
        while let Some(arg) = args.next() {
            position += 1;
            if arg == subcommand {
                continue;
            }
            // Errors below name the flag but never repeat a value: a value
            // given by mistake (`-p=…`, a misspelt `--pasword=…`, a bare
            // word) may well be the password.
            if !arg.starts_with('-') {
                return Err(format!(
                    "unexpected argument {position}: a value with no flag before it (expected \
                     --server, --user, --domain, --port or --service)"
                ));
            }
            let (name, inline) = match arg.split_once('=') {
                Some((name, value)) => (name.to_string(), Some(value.to_string())),
                None => (arg, None),
            };
            let mut value = || {
                let value = match inline.clone() {
                    Some(v) => v,
                    None => args.next().unwrap_or_default(),
                };
                if value.is_empty() {
                    Err(format!("{name} needs a value"))
                } else {
                    Ok(value)
                }
            };
            match name.as_str() {
                "--server" => {
                    self.server = Some(Setting {
                        value: value()?,
                        from: "--server",
                    });
                }
                "--port" => {
                    self.port = Some(Setting {
                        value: value()?,
                        from: "--port",
                    });
                }
                "--user" => self.user = Some(value()?),
                "--domain" => self.domain = value()?,
                "--service" => self.service = Some(value()?),
                "--password" | "--pass" | "--smb-pass" | "-p" => {
                    return Err(format!(
                        "{name}: the password is never taken from the command line, where any \
                         process can read it from the process list. Leave it out and type it \
                         when asked, or pipe it in on standard input"
                    ));
                }
                _ => {
                    return Err(format!(
                        "unknown flag {name:?} (expected --server, --user, --domain, --port or \
                         --service)"
                    ));
                }
            }
        }
        Ok(self)
    }

    /// The SMB port: the setting, or 445.
    pub fn port(&self) -> Result<u16, String> {
        match &self.port {
            None => Ok(DEFAULT_PORT),
            Some(Setting { value, from }) => {
                parse_port(value).ok_or_else(|| format!("{from}={value} is not a valid port"))
            }
        }
    }

    /// The destination: server (checked to be a host), port, user and domain.
    /// Startup connects to exactly this, and the keychain item is keyed on it.
    pub fn destination(&self) -> Result<Destination, String> {
        let (Some(server), Some(user)) = (&self.server, &self.user) else {
            return Err(
                "the SMB server and user are required (--server/--user, or SPICEIO_SMB_SERVER/\
                 SPICEIO_SMB_USER): the keychain item is keyed on them"
                    .into(),
            );
        };
        check_server(server.from, &server.value)?;
        Ok(Destination {
            server: server.value.clone(),
            port: self.port()?,
            user: user.clone(),
            domain: self.domain.clone(),
        })
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
    /// A keychain item, and its destination as output may show it
    /// ([`shown`]).
    Keychain {
        /// The item.
        item: Item,
        /// `smb://****@server[:port]`.
        shown: String,
    },
}

impl Source {
    /// Decide the source from the settings, without reading the keychain.
    pub fn resolve(settings: &Settings) -> Result<Self, String> {
        match (&settings.inline, &settings.service) {
            (Some(_), Some(_)) => {
                Err("set one of SPICEIO_SMB_PASS and SPICEIO_SMB_PASS_KEYCHAIN, not both".into())
            }
            (Some(password), None) => Ok(Self::Env(password.clone())),
            (None, Some(service)) => Ok(Self::Keychain {
                item: settings.item(service)?,
                shown: shown(&settings.destination()?),
            }),
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
            Self::Keychain { item, shown } => format!(
                "keychain item \"{}\" for {shown} ({})",
                item.service,
                item.location()
            ),
        }
    }

    /// The password, read from wherever it lives. Keychain failures come
    /// back as a sentence that says what to do about them.
    pub fn load(&self) -> Result<String, String> {
        match self {
            Self::Env(password) => Ok(password.clone()),
            Self::Keychain { item, shown } => {
                let bytes = keychain::read(item).map_err(|e| explain(item, shown, &e, false))?;
                let password = String::from_utf8(bytes).map_err(|_| {
                    format!(
                        "keychain item \"{}\" for {shown} is not UTF-8 text",
                        item.service
                    )
                })?;
                if password.is_empty() {
                    return Err(format!(
                        "keychain item \"{}\" for {shown} is empty",
                        item.service
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

/// The `security delete-generic-password` command that removes `item`, with
/// `<user>` standing in for the SMB user (output never shows it).
fn delete_command(item: &Item, shown: &str) -> String {
    let account = shown.replacen("****", "<user>", 1);
    let mut cmd = format!(
        "security delete-generic-password -s {} -a {}",
        sh_quote(&item.service),
        sh_quote(&account)
    );
    if let Some(path) = &item.keychain {
        cmd.push(' ');
        cmd.push_str(&sh_quote(&path.display().to_string()));
    }
    cmd
}

/// A keychain failure as a sentence that says what to do. `storing`: the
/// failure came from `--store-smb-password`, which leaves an unreadable item
/// alone rather than overwrite it.
fn explain(item: &Item, shown: &str, e: &keychain::Error, storing: bool) -> String {
    let what = format!("keychain item \"{}\" for {shown}", item.service);
    match e {
        keychain::Error::NotFound => format!(
            "no {what} in {}. Store the password with `spiceio --store-smb-password` and the \
             same server, user, domain and port: the item is keyed on them",
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
            let (outcome, remedy) = if storing {
                (
                    "exists but this binary cannot read it, so it was left alone",
                    "To replace it, delete it first",
                )
            } else {
                (
                    "cannot be read by this binary",
                    "Install with `make install`, which signs with the same local identity every \
                     time, or delete it",
                )
            };
            format!(
                "{what} {outcome}: this binary's signature ({signature}) is not on the item's \
                 access list, so a binary with another signature stored it. {remedy} ({}, with \
                 your SMB user for <user>, as DOMAIN;user if a domain is set; macOS may ask for \
                 your login password) and run `spiceio --store-smb-password` again",
                delete_command(item, shown)
            )
        }
        keychain::Error::NoSuchKeychain => match &item.keychain {
            Some(path) => format!(
                "keychain {} does not exist (SPICEIO_SMB_PASS_KEYCHAIN_PATH)",
                path.display()
            ),
            None => format!(
                "the login keychain ({}) does not exist",
                keychain::login_keychain()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "no home directory".into())
            ),
        },
        other => format!("{what} in {}: {other}", item.location()),
    }
}

/// The settings for a subcommand: the environment, then `args` over it.
fn settings_for(args: &[String], subcommand: &str) -> Result<Settings, String> {
    Settings::from_env().with_args(args.iter().skip(1), subcommand)
}

/// `spiceio --check-smb-password [flags]`: resolve the password the way
/// startup does, report where it came from, exit 0; or say why it cannot,
/// exit 1. Touches nothing else (no SMB, no listener, no log file).
pub fn check_command(args: &[String]) -> i32 {
    let source = match settings_for(args, "--check-smb-password").and_then(|s| Source::resolve(&s))
    {
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

/// `spiceio --store-smb-password [flags]`: store the SMB password for the
/// configured server and user in the keychain, then read it back.
///
/// The password comes from the terminal (asked twice, without echo) or, when
/// standard input is not a terminal, from all of standard input less one
/// trailing newline, so `plutil -extract … raw` can be piped in. It is never
/// taken from `SPICEIO_SMB_PASS`: a password in the environment is what this
/// replaces, and taking it from there would invite putting it on a command
/// line.
pub fn store_command(args: &[String]) -> i32 {
    match store(args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("spiceio --store-smb-password: {e}");
            1
        }
    }
}

fn store(args: &[String]) -> Result<(), String> {
    let settings = settings_for(args, "--store-smb-password")?;
    if settings.inline.is_some() {
        return Err(
            "SPICEIO_SMB_PASS is set. This command reads the password from the terminal or \
             standard input, never from the environment; unset it"
                .into(),
        );
    }
    let service = settings.service.as_deref().unwrap_or(DEFAULT_SERVICE);
    let item = settings.item(service)?;
    let place = shown(&settings.destination()?);
    let signature = keychain::own_signature().map_err(|e| format!("code signature: {e}"))?;
    if signature.adhoc {
        eprintln!(
            "warning: this spiceio binary is ad-hoc signed ({}). The keychain item will be \
             readable by this exact build only; every rebuild is a different signature. Store \
             it with a binary `make install` signed instead.",
            signature.requirement
        );
    }
    let mut password = read_password(&place)?;
    let label = format!("spiceio SMB password ({})", item.account);
    let result = keychain::store(&item, &label, &password);
    wipe(&mut password);
    let stored = result.map_err(|e| explain(&item, &place, &e, true))?;
    println!(
        "SMB password for {place}: {stored} in keychain item \"{}\" ({})",
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

fn read_password(place: &str) -> Result<Vec<u8>, String> {
    let password = if std::io::stdin().is_terminal() {
        let mut first = prompt(&format!("SMB password for {place}: "))?;
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

    fn settings(vars: &[(&str, &str)]) -> Settings {
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
        let a = Source::resolve(&settings(&base)).unwrap();
        let b = Source::resolve(&settings(&moved)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn inline_password_is_the_env_source() {
        let s = settings(&[("SPICEIO_SMB_PASS", "secret")]);
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
        ]);
        let source = Source::resolve(&s).unwrap();
        assert_eq!(
            source,
            Source::Keychain {
                item: Item {
                    service: "svc".into(),
                    account: "smb://u@nas".into(),
                    keychain: Some("/tmp/k.keychain-db".into()),
                },
                shown: "smb://****@nas".into(),
            }
        );
        // The user name never appears in output.
        assert_eq!(
            source.describe(),
            "keychain item \"svc\" for smb://****@nas (keychain /tmp/k.keychain-db)"
        );
    }

    #[test]
    fn both_or_neither_is_an_error() {
        let both = settings(&[
            ("SPICEIO_SMB_SERVER", "nas"),
            ("SPICEIO_SMB_USER", "u"),
            ("SPICEIO_SMB_PASS", "p"),
            ("SPICEIO_SMB_PASS_KEYCHAIN", "svc"),
        ]);
        assert!(Source::resolve(&both).unwrap_err().contains("not both"));
        let neither = settings(&[("SPICEIO_SMB_SERVER", "nas"), ("SPICEIO_SMB_USER", "u")]);
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
        ]);
        assert!(matches!(Source::resolve(&s), Ok(Source::Keychain { .. })));
    }

    #[test]
    fn keychain_needs_server_and_user_and_an_absolute_path() {
        let s = settings(&[("SPICEIO_SMB_PASS_KEYCHAIN", "svc")]);
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
        ]);
        assert!(
            Source::resolve(&s)
                .unwrap_err()
                .contains("not an absolute path")
        );
    }

    #[test]
    fn server_must_be_a_host() {
        for ok in [
            "nas.local",
            "192.168.3.148",
            "fe80::1",
            "[fe80::1]",
            "nas-01",
        ] {
            assert_eq!(check_server("--server", ok), Ok(()), "{ok}");
        }
        let err = check_server("--server", "smb://192.168.3.148").unwrap_err();
        assert!(
            err.contains("is a URL") && err.contains("(use 192.168.3.148)"),
            "{err}"
        );
        let err = check_server("--server", "smb://alice@nas.local/share").unwrap_err();
        assert!(err.contains("(use nas.local)"), "{err}");
        let err = check_server("SPICEIO_SMB_SERVER", "nas.local:4455").unwrap_err();
        assert!(
            err.contains("includes a port") && err.contains("(nas.local)"),
            "{err}"
        );
        assert!(check_server("--server", "nas.local/share").is_err());
        assert!(check_server("--server", "nas local").is_err());
        let with_user = |server: &str| {
            settings(&[("SPICEIO_SMB_SERVER", server), ("SPICEIO_SMB_USER", "u")]).destination()
        };
        assert!(with_user("smb://nas").is_err());
        assert!(
            Settings::default()
                .with_args(args(&["--server", "smb://nas", "--user", "u"]), "-")
                .unwrap()
                .destination()
                .is_err()
        );
    }

    #[test]
    fn server_errors_never_repeat_user_info() {
        for value in [
            "smb://alice:hunter2@nas.local/share",
            "smb://alice:pa/ss@nas.local",
            "alice:hunter2@nas.local",
            "smb://alice@nas.local",
        ] {
            let err = check_server("SPICEIO_SMB_SERVER", value).unwrap_err();
            for secret in ["alice", "hunter2", "pa/ss"] {
                assert!(!err.contains(secret), "{value}: {err}");
            }
            assert!(err.contains("****@nas.local"), "{value}: {err}");
            assert!(err.contains("(use nas.local)"), "{value}: {err}");
        }
    }

    #[test]
    fn port_parsing_is_shared_and_ignores_whitespace() {
        assert_eq!(parse_port(" 4455 "), Some(4455));
        assert_eq!(parse_port("smb"), None);
        assert_eq!(settings(&[("SPICEIO_SMB_PORT", " 4455 ")]).port(), Ok(4455));
        assert_eq!(
            settings(&[("SPICEIO_SMB_PORT", "   ")]).port(),
            Ok(DEFAULT_PORT)
        );
    }

    #[test]
    fn bad_port_is_an_error() {
        assert_eq!(
            settings(&[("SPICEIO_SMB_PORT", "smb")]).port(),
            Err("SPICEIO_SMB_PORT=smb is not a valid port".into())
        );
    }

    /// Flags are applied before anything is checked, so a flag can replace an
    /// environment value that would not pass.
    #[test]
    fn a_flag_overrides_an_invalid_environment_value() {
        let s = settings(&[
            ("SPICEIO_SMB_SERVER", "smb://nas"),
            ("SPICEIO_SMB_PORT", "smb"),
            ("SPICEIO_SMB_USER", "u"),
        ])
        .with_args(args(&["--server", "nas", "--port", "4455"]), "-")
        .unwrap();
        assert_eq!(account(&s.destination().unwrap()), "smb://u@nas:4455");
    }

    #[test]
    fn shown_masks_the_user_and_domain() {
        assert_eq!(
            shown(&dest("nas.local", 445, "alice", "CORP")),
            "smb://****@nas.local"
        );
        assert_eq!(
            shown(&dest("fe80::1", 4455, "alice", "")),
            "smb://****@[fe80::1]:4455"
        );
    }

    #[test]
    fn suggestions_quote_for_the_shell_and_leave_out_the_user() {
        let item = Item {
            service: "it's".into(),
            account: "smb://CORP;alice@nas".into(),
            keychain: None,
        };
        assert_eq!(
            delete_command(&item, "smb://****@nas"),
            r"security delete-generic-password -s 'it'\''s' -a 'smb://<user>@nas'"
        );
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_override_the_environment() {
        let env = settings(&[
            ("SPICEIO_SMB_SERVER", "env-nas"),
            ("SPICEIO_SMB_USER", "env-user"),
            ("SPICEIO_SMB_PORT", "4455"),
        ]);
        let s = env
            .with_args(
                args(&[
                    "--store-smb-password",
                    "--server",
                    "flag-nas",
                    "--user=flag-user",
                    "--domain",
                    "CORP",
                    "--service=svc",
                ]),
                "--store-smb-password",
            )
            .unwrap();
        assert_eq!(
            s.server.as_ref().map(|v| v.value.as_str()),
            Some("flag-nas")
        );
        assert_eq!(s.user.as_deref(), Some("flag-user"));
        assert_eq!(s.domain, "CORP");
        assert_eq!(s.service.as_deref(), Some("svc"));
        assert_eq!(
            s.port(),
            Ok(4455),
            "an unflagged setting keeps its environment value"
        );
        assert_eq!(
            account(&s.destination().unwrap()),
            "smb://CORP;flag-user@flag-nas:4455"
        );
    }

    #[test]
    fn flags_alone_are_enough() {
        let s = Settings::default()
            .with_args(
                args(&["--server", "nas", "--user", "u", "--port", "445"]),
                "-",
            )
            .unwrap();
        assert_eq!(account(&s.destination().unwrap()), "smb://u@nas");
    }

    #[test]
    fn password_flags_are_refused() {
        for flag in ["--password", "--pass", "--smb-pass", "-p"] {
            let err = Settings::default()
                .with_args(args(&[flag, "hunter2"]), "-")
                .unwrap_err();
            assert!(
                err.contains("never taken from the command line"),
                "{flag}: {err}"
            );
        }
        let err = Settings::default()
            .with_args(args(&["--password=hunter2"]), "-")
            .unwrap_err();
        assert!(
            !err.contains("hunter2"),
            "the refusal must not echo it: {err}"
        );
    }

    /// No refusal repeats a value: one typed by mistake may be the password.
    #[test]
    fn refusals_never_echo_a_value() {
        for list in [
            &["-p=hunter2"][..],
            &["--password=hunter2"],
            &["--pasword=hunter2"],
            &["hunter2"],
            &["--server", "nas", "hunter2"],
        ] {
            let err = Settings::default().with_args(args(list), "-").unwrap_err();
            assert!(!err.contains("hunter2"), "{list:?}: {err}");
        }
        let err = Settings::default()
            .with_args(args(&["-p=hunter2"]), "-")
            .unwrap_err();
        assert!(err.contains("never taken from the command line"), "{err}");
    }

    #[test]
    fn a_password_of_spaces_is_a_password() {
        let s = settings(&[("SPICEIO_SMB_PASS", "   ")]);
        assert_eq!(Source::resolve(&s), Ok(Source::Env("   ".into())));
    }

    #[test]
    fn bad_flags_are_errors() {
        assert!(
            Settings::default()
                .with_args(args(&["--server"]), "-")
                .unwrap_err()
                .contains("needs a value")
        );
        assert!(
            Settings::default()
                .with_args(args(&["--server="]), "-")
                .unwrap_err()
                .contains("needs a value")
        );
        assert!(
            Settings::default()
                .with_args(args(&["--port", "smb"]), "-")
                .unwrap()
                .port()
                .unwrap_err()
                .contains("--port=smb is not a valid port")
        );
        assert!(
            Settings::default()
                .with_args(args(&["--serverr", "x"]), "-")
                .unwrap_err()
                .contains("unknown flag \"--serverr\"")
        );
        assert!(
            Settings::default()
                .with_args(args(&["nas"]), "-")
                .unwrap_err()
                .contains("unexpected argument 1")
        );
    }
}
