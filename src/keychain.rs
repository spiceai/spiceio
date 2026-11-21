//! macOS Keychain access through Security.framework, for secrets spiceio would
//! otherwise take from its environment (today: the SMB password).
//!
//! # What the keychain buys over an environment variable
//!
//! A password in a launchd plist is plaintext on disk and in every backup of
//! it, and `launchctl print` shows a loaded job's environment to any process
//! running as the same user. A generic-password item in a file-based keychain
//! is encrypted at rest, and its **access list names the code signature that
//! may read it**: a process whose signature does not satisfy that requirement
//! is refused (or, with UI allowed, would make macOS ask the user).
//!
//! The access list holds the designated requirement of the binary that
//! created the item. For an ad-hoc signature (what `cargo build` produces)
//! that is the binary's cdhash, which every rebuild changes. For a binary
//! signed with a certificate it is `identifier "…" and certificate leaf =
//! H"…"`, which survives rebuilds signed with the same certificate. That is
//! why `make install` signs with a stable local identity
//! (`scripts/codesign-local.sh`); no Apple Developer account is needed.
//!
//! # What it does not buy
//!
//! The default access list lets *any* application replace an item's data:
//! only reading is restricted. A process running as the same user cannot
//! read the password, but it can overwrite it with a value of its own. Every
//! write path here therefore reads first and refuses to write an item it
//! cannot read, and callers key the item on everything that says *where* the
//! secret may be sent (see [`crate::smb_password::account`]), so a changed
//! destination finds no item instead of handing the real secret to it.
//!
//! # Never prompt
//!
//! spiceio runs unattended under launchd. Every operation here runs with
//! keychain user interaction disabled, so a locked keychain or a signature
//! that is not on the access list fails immediately with a status instead of
//! blocking on a dialog nobody may be there to answer. Interaction is a
//! process-wide setting, so it is switched off and restored under one lock.
//!
//! The legacy keychain calls used here (`SecKeychainOpen`, `GetStatus`,
//! `SetUserInteractionAllowed`) are deprecated but remain the only way to
//! address a file-based keychain by path and to suppress its prompts. Items
//! are read and written with the `SecItem` API.

use std::ffi::{CString, c_char, c_void};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

type CFTypeRef = *const c_void;
type CFIndex = isize;
type OSStatus = i32;
type Boolean = u8;

/// Opaque `CFDictionaryKeyCallBacks` / `CFArrayCallBacks`: only their
/// addresses are ever passed.
#[repr(C)]
struct CallBacks {
    _opaque: [u8; 0],
}

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const K_CF_NUMBER_SINT64_TYPE: CFIndex = 4;

const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;
const ERR_SEC_AUTH_FAILED: OSStatus = -25293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: OSStatus = -25308;
const ERR_SEC_NO_SUCH_KEYCHAIN: OSStatus = -25294;

const K_SEC_UNLOCK_STATE_STATUS: u32 = 1;
const K_SEC_CS_DEFAULT_FLAGS: u32 = 0;
const K_SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;
const K_SEC_CODE_SIGNATURE_ADHOC: i64 = 0x0002;

#[allow(non_upper_case_globals)]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFBooleanTrue: CFTypeRef;
    static kCFTypeDictionaryKeyCallBacks: CallBacks;
    static kCFTypeDictionaryValueCallBacks: CallBacks;
    static kCFTypeArrayCallBacks: CallBacks;

    fn CFRelease(cf: CFTypeRef);
    fn CFGetTypeID(cf: CFTypeRef) -> usize;
    fn CFDataGetTypeID() -> usize;
    fn CFStringCreateWithBytes(
        alloc: CFTypeRef,
        bytes: *const u8,
        len: CFIndex,
        encoding: u32,
        is_external: Boolean,
    ) -> CFTypeRef;
    fn CFDataCreate(alloc: CFTypeRef, bytes: *const u8, len: CFIndex) -> CFTypeRef;
    fn CFDataGetLength(data: CFTypeRef) -> CFIndex;
    fn CFDataGetBytePtr(data: CFTypeRef) -> *const u8;
    fn CFDictionaryCreate(
        alloc: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: CFIndex,
        key_callbacks: *const CallBacks,
        value_callbacks: *const CallBacks,
    ) -> CFTypeRef;
    fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn CFArrayCreate(
        alloc: CFTypeRef,
        values: *const CFTypeRef,
        count: CFIndex,
        callbacks: *const CallBacks,
    ) -> CFTypeRef;
    fn CFStringGetLength(s: CFTypeRef) -> CFIndex;
    fn CFStringGetMaximumSizeForEncoding(len: CFIndex, encoding: u32) -> CFIndex;
    fn CFStringGetCString(s: CFTypeRef, buf: *mut c_char, size: CFIndex, encoding: u32) -> Boolean;
    fn CFNumberGetValue(number: CFTypeRef, kind: CFIndex, out: *mut c_void) -> Boolean;
}

#[allow(non_upper_case_globals)]
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecClass: CFTypeRef;
    static kSecClassGenericPassword: CFTypeRef;
    static kSecAttrService: CFTypeRef;
    static kSecAttrAccount: CFTypeRef;
    static kSecAttrLabel: CFTypeRef;
    static kSecValueData: CFTypeRef;
    static kSecReturnData: CFTypeRef;
    static kSecMatchLimit: CFTypeRef;
    static kSecMatchLimitOne: CFTypeRef;
    static kSecMatchSearchList: CFTypeRef;
    static kSecUseKeychain: CFTypeRef;
    static kSecUseAuthenticationUI: CFTypeRef;
    static kSecUseAuthenticationUIFail: CFTypeRef;
    static kSecCodeInfoFlags: CFTypeRef;

    fn SecItemCopyMatching(query: CFTypeRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemAdd(attributes: CFTypeRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemUpdate(query: CFTypeRef, attributes: CFTypeRef) -> OSStatus;
    fn SecKeychainOpen(path: *const c_char, keychain: *mut CFTypeRef) -> OSStatus;
    fn SecKeychainGetStatus(keychain: CFTypeRef, status: *mut u32) -> OSStatus;
    fn SecKeychainGetUserInteractionAllowed(state: *mut Boolean) -> OSStatus;
    fn SecKeychainSetUserInteractionAllowed(state: Boolean) -> OSStatus;
    fn SecCopyErrorMessageString(status: OSStatus, reserved: *mut c_void) -> CFTypeRef;
    fn SecCodeCopySelf(flags: u32, code: *mut CFTypeRef) -> OSStatus;
    fn SecCodeCopyStaticCode(code: CFTypeRef, flags: u32, static_code: *mut CFTypeRef) -> OSStatus;
    fn SecCodeCopySigningInformation(
        code: CFTypeRef,
        flags: u32,
        information: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecCodeCopyDesignatedRequirement(
        code: CFTypeRef,
        flags: u32,
        requirement: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecRequirementCopyString(
        requirement: CFTypeRef,
        flags: u32,
        text: *mut CFTypeRef,
    ) -> OSStatus;
}

/// An owned CoreFoundation object, released on drop.
struct Cf(CFTypeRef);

impl Cf {
    fn new(ptr: CFTypeRef) -> Option<Self> {
        (!ptr.is_null()).then_some(Self(ptr))
    }
}

impl Drop for Cf {
    fn drop(&mut self) {
        // SAFETY: `Cf` is only built from a non-null object this code owns
        // (a Create/Copy result), released exactly once here.
        unsafe { CFRelease(self.0) }
    }
}

fn cf_string(s: &str) -> Result<Cf, Error> {
    // SAFETY: the bytes outlive the call; CF copies them.
    let ptr = unsafe {
        CFStringCreateWithBytes(
            std::ptr::null(),
            s.as_ptr(),
            s.len() as CFIndex,
            K_CF_STRING_ENCODING_UTF8,
            0,
        )
    };
    Cf::new(ptr).ok_or_else(|| Error::Invalid("CFStringCreateWithBytes failed".into()))
}

fn cf_data(bytes: &[u8]) -> Result<Cf, Error> {
    // SAFETY: the bytes outlive the call; CF copies them.
    let ptr = unsafe { CFDataCreate(std::ptr::null(), bytes.as_ptr(), bytes.len() as CFIndex) };
    Cf::new(ptr).ok_or_else(|| Error::Invalid("CFDataCreate failed".into()))
}

/// A CFDictionary of CF-type keys and values (both retained by the dictionary).
fn cf_dict(pairs: &[(CFTypeRef, CFTypeRef)]) -> Result<Cf, Error> {
    let keys: Vec<CFTypeRef> = pairs.iter().map(|p| p.0).collect();
    let values: Vec<CFTypeRef> = pairs.iter().map(|p| p.1).collect();
    // SAFETY: both arrays hold `pairs.len()` valid CF objects for the call;
    // the CFType callbacks retain them for the dictionary's lifetime.
    let ptr = unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            pairs.len() as CFIndex,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
        )
    };
    Cf::new(ptr).ok_or_else(|| Error::Invalid("CFDictionaryCreate failed".into()))
}

/// Copy a CFString (borrowed, not consumed) into a Rust `String`.
fn string_from_cf(s: CFTypeRef) -> Option<String> {
    if s.is_null() {
        return None;
    }
    // SAFETY: `s` is a valid CFString for the duration of these calls, and
    // the buffer is sized by CF's own bound for UTF-8 plus the terminator.
    unsafe {
        let len = CFStringGetLength(s);
        let cap = CFStringGetMaximumSizeForEncoding(len, K_CF_STRING_ENCODING_UTF8) + 1;
        let mut buf = vec![0u8; usize::try_from(cap).ok()?];
        if CFStringGetCString(s, buf.as_mut_ptr().cast(), cap, K_CF_STRING_ENCODING_UTF8) == 0 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        buf.truncate(end);
        String::from_utf8(buf).ok()
    }
}

fn status_message(status: OSStatus) -> String {
    // SAFETY: returns a new CFString (or null) that `Cf` releases.
    let msg = Cf::new(unsafe { SecCopyErrorMessageString(status, std::ptr::null_mut()) });
    msg.and_then(|m| string_from_cf(m.0))
        .unwrap_or_else(|| "unknown error".into())
}

/// What went wrong talking to the keychain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No item with this service and account.
    NotFound,
    /// The item exists but this process may not read it: the keychain is
    /// locked, or the item's access list does not include this binary's
    /// signature. Both come back from Security.framework as the same status,
    /// so `locked` records what a separate status query found.
    Denied {
        /// The keychain reported itself locked.
        locked: bool,
    },
    /// The named keychain file does not exist.
    NoSuchKeychain,
    /// Any other Security.framework status.
    Os {
        /// The OSStatus.
        status: i32,
        /// Security.framework's description of it.
        message: String,
    },
    /// Bad input, or a result of an unexpected shape.
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such keychain item"),
            Self::Denied { locked: true } => f.write_str("the keychain is locked"),
            Self::Denied { locked: false } => {
                f.write_str("this binary's signature is not on the item's access list")
            }
            Self::NoSuchKeychain => f.write_str("the keychain does not exist"),
            Self::Os { status, message } => write!(f, "{message} (OSStatus {status})"),
            Self::Invalid(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for Error {}

/// One generic-password item: `service` + `account`, in `keychain` (a
/// keychain file) or, when that is `None`, the user's keychain search list
/// (normally just the login keychain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// `kSecAttrService`.
    pub service: String,
    /// `kSecAttrAccount`.
    pub account: String,
    /// A keychain file to use instead of the user's search list.
    pub keychain: Option<PathBuf>,
}

impl Item {
    /// Where the item lives, for messages.
    pub fn location(&self) -> String {
        match &self.keychain {
            Some(path) => format!("keychain {}", path.display()),
            None => "the login keychain".into(),
        }
    }
}

/// How [`store`] left the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    /// There was none; it was created.
    Added,
    /// It held a different secret, which was replaced.
    Updated,
    /// It already held this secret; nothing was written.
    Unchanged,
}

impl fmt::Display for Stored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Added => "added",
            Self::Updated => "updated",
            Self::Unchanged => "unchanged",
        })
    }
}

/// Serializes keychain operations, so the process-wide user-interaction
/// setting is switched off and restored without interleaving.
static KEYCHAIN: Mutex<()> = Mutex::new(());

/// Keychain user interaction disabled for this guard's lifetime.
struct NoPrompts {
    previous: Boolean,
    _lock: MutexGuard<'static, ()>,
}

impl NoPrompts {
    fn new() -> Self {
        let lock = KEYCHAIN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut previous: Boolean = 1;
        // SAFETY: plain out-parameter / value calls.
        unsafe {
            SecKeychainGetUserInteractionAllowed(&mut previous);
            SecKeychainSetUserInteractionAllowed(0);
        }
        Self {
            previous,
            _lock: lock,
        }
    }
}

impl Drop for NoPrompts {
    fn drop(&mut self) {
        // SAFETY: plain value call.
        unsafe {
            SecKeychainSetUserInteractionAllowed(self.previous);
        }
    }
}

fn open_keychain(path: &Path) -> Result<Cf, Error> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::Invalid(format!("keychain path {} contains NUL", path.display())))?;
    let mut keychain: CFTypeRef = std::ptr::null();
    // SAFETY: `c_path` is NUL-terminated and outlives the call; the result is
    // a new reference that `Cf` releases. Opening does not touch the file.
    let status = unsafe { SecKeychainOpen(c_path.as_ptr(), &mut keychain) };
    if status != 0 {
        return Err(os_error(status));
    }
    Cf::new(keychain).ok_or_else(|| Error::Invalid("SecKeychainOpen returned null".into()))
}

/// Locked/unlocked state of `keychain` (null: the default keychain).
fn keychain_locked(keychain: CFTypeRef) -> Result<bool, Error> {
    let mut status_bits: u32 = 0;
    // SAFETY: `keychain` is null or a valid SecKeychainRef; out-parameter.
    let status = unsafe { SecKeychainGetStatus(keychain, &mut status_bits) };
    match status {
        0 => Ok(status_bits & K_SEC_UNLOCK_STATE_STATUS == 0),
        ERR_SEC_NO_SUCH_KEYCHAIN => Err(Error::NoSuchKeychain),
        other => Err(os_error(other)),
    }
}

/// Whether the keychain file at `path` is unlocked. Never prompts, and never
/// unlocks: `make install` uses it to decide whether it must ask for the
/// signing keychain's password before calling `codesign`, which would
/// otherwise raise an unlock dialog.
pub fn keychain_unlocked(path: &Path) -> Result<bool, Error> {
    let _no_prompts = NoPrompts::new();
    let keychain = open_keychain(path)?;
    keychain_locked(keychain.0).map(|locked| !locked)
}

fn os_error(status: OSStatus) -> Error {
    Error::Os {
        status,
        message: status_message(status),
    }
}

/// The keychain file an item addresses, opened, and the one-element search
/// list built from it. Both stay alive for as long as a query uses them.
struct Target {
    keychain: Option<Cf>,
    search_list: Option<Cf>,
}

impl Target {
    fn new(item: &Item) -> Result<Self, Error> {
        let Some(path) = &item.keychain else {
            return Ok(Self {
                keychain: None,
                search_list: None,
            });
        };
        let keychain = open_keychain(path)?;
        // A file that does not exist opens fine and only fails later with a
        // vaguer status; ask now so the error names the real problem.
        keychain_locked(keychain.0)?;
        let values = [keychain.0];
        // SAFETY: one valid CF object; the array retains it.
        let list = unsafe {
            CFArrayCreate(
                std::ptr::null(),
                values.as_ptr(),
                1,
                &raw const kCFTypeArrayCallBacks,
            )
        };
        let search_list =
            Cf::new(list).ok_or_else(|| Error::Invalid("CFArrayCreate failed".into()))?;
        Ok(Self {
            keychain: Some(keychain),
            search_list: Some(search_list),
        })
    }

    /// Map a refusal to [`Error::Denied`], with the lock state the status
    /// itself does not carry.
    fn classify(&self, status: OSStatus) -> Error {
        match status {
            ERR_SEC_ITEM_NOT_FOUND => Error::NotFound,
            ERR_SEC_NO_SUCH_KEYCHAIN => Error::NoSuchKeychain,
            ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED => {
                let keychain = self.keychain.as_ref().map_or(std::ptr::null(), |k| k.0);
                Error::Denied {
                    locked: keychain_locked(keychain).unwrap_or(false),
                }
            }
            other => os_error(other),
        }
    }
}

/// The attributes that identify `item` in a query: class, service, account,
/// and the search list when a keychain file is named.
fn identity_pairs(
    item_keys: &(Cf, Cf),
    target: &Target,
    extra: &[(CFTypeRef, CFTypeRef)],
) -> Vec<(CFTypeRef, CFTypeRef)> {
    // SAFETY: reading immutable framework constants.
    let mut pairs = unsafe {
        vec![
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, item_keys.0.0),
            (kSecAttrAccount, item_keys.1.0),
        ]
    };
    if let Some(list) = &target.search_list {
        // SAFETY: reading an immutable framework constant.
        pairs.push((unsafe { kSecMatchSearchList }, list.0));
    }
    pairs.extend_from_slice(extra);
    pairs
}

fn item_keys(item: &Item) -> Result<(Cf, Cf), Error> {
    if item.service.is_empty() || item.account.is_empty() {
        return Err(Error::Invalid(
            "a keychain item needs a service and an account".into(),
        ));
    }
    Ok((cf_string(&item.service)?, cf_string(&item.account)?))
}

/// Read `item`'s secret. Caller holds a [`NoPrompts`].
fn read_unlocked(item: &Item, target: &Target, keys: &(Cf, Cf)) -> Result<Vec<u8>, Error> {
    // SAFETY: reading immutable framework constants.
    let extra = unsafe {
        [
            (kSecReturnData, kCFBooleanTrue),
            (kSecMatchLimit, kSecMatchLimitOne),
            // Belt and braces with `NoPrompts`: fail rather than prompt.
            (kSecUseAuthenticationUI, kSecUseAuthenticationUIFail),
        ]
    };
    let query = cf_dict(&identity_pairs(keys, target, &extra))?;
    let mut result: CFTypeRef = std::ptr::null();
    // SAFETY: valid query dictionary; out-parameter receives a new reference.
    let status = unsafe { SecItemCopyMatching(query.0, &mut result) };
    if status != 0 {
        return Err(target.classify(status));
    }
    let data = Cf::new(result).ok_or_else(|| Error::Invalid("keychain returned no data".into()))?;
    // SAFETY: `data` is a valid CF object; its type is checked before it is
    // read as CFData, and the bytes are copied while it is alive.
    unsafe {
        if CFGetTypeID(data.0) != CFDataGetTypeID() {
            return Err(Error::Invalid(format!(
                "keychain item {} returned something other than data",
                item.service
            )));
        }
        let len = usize::try_from(CFDataGetLength(data.0)).unwrap_or(0);
        let ptr = CFDataGetBytePtr(data.0);
        if len == 0 || ptr.is_null() {
            return Ok(Vec::new());
        }
        Ok(std::slice::from_raw_parts(ptr, len).to_vec())
    }
}

/// Read `item`'s secret, without prompting.
pub fn read(item: &Item) -> Result<Vec<u8>, Error> {
    let _no_prompts = NoPrompts::new();
    let target = Target::new(item)?;
    let keys = item_keys(item)?;
    read_unlocked(item, &target, &keys)
}

/// Create or update `item` so it holds `secret`, without prompting, and read
/// it back to prove this binary can.
///
/// An item that exists but cannot be read is refused rather than written:
/// the keychain would accept the write (any application may replace an
/// item's data), but the item would keep an access list this binary is not
/// on, so the write would only destroy the old secret. A new item's access
/// list is this binary's designated requirement.
pub fn store(item: &Item, label: &str, secret: &[u8]) -> Result<Stored, Error> {
    if secret.is_empty() {
        return Err(Error::Invalid("refusing to store an empty secret".into()));
    }
    let _no_prompts = NoPrompts::new();
    let target = Target::new(item)?;
    let keys = item_keys(item)?;
    let data = cf_data(secret)?;
    let outcome = match read_unlocked(item, &target, &keys) {
        Ok(current) if current == secret => Stored::Unchanged,
        Ok(_) => {
            let query = cf_dict(&identity_pairs(&keys, &target, &[]))?;
            // SAFETY: reading an immutable framework constant.
            let update = cf_dict(&[(unsafe { kSecValueData }, data.0)])?;
            // SAFETY: valid dictionaries.
            let status = unsafe { SecItemUpdate(query.0, update.0) };
            if status != 0 {
                return Err(target.classify(status));
            }
            Stored::Updated
        }
        Err(Error::NotFound) => {
            let label = cf_string(label)?;
            // SAFETY: reading immutable framework constants.
            let mut pairs = unsafe {
                vec![
                    (kSecClass, kSecClassGenericPassword),
                    (kSecAttrService, keys.0.0),
                    (kSecAttrAccount, keys.1.0),
                    (kSecAttrLabel, label.0),
                    (kSecValueData, data.0),
                ]
            };
            if let Some(keychain) = &target.keychain {
                // SAFETY: reading an immutable framework constant.
                pairs.push((unsafe { kSecUseKeychain }, keychain.0));
            }
            let attributes = cf_dict(&pairs)?;
            // SAFETY: valid dictionary; no result requested.
            let status = unsafe { SecItemAdd(attributes.0, std::ptr::null_mut()) };
            if status != 0 {
                return Err(target.classify(status));
            }
            Stored::Added
        }
        Err(e) => return Err(e),
    };
    match read_unlocked(item, &target, &keys) {
        Ok(back) if back == secret => Ok(outcome),
        Ok(_) => Err(Error::Invalid(
            "the keychain item reads back different from what was stored".into(),
        )),
        Err(e) => Err(e),
    }
}

/// This process's code signature, as the keychain sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Ad-hoc (no certificate): the designated requirement is the cdhash,
    /// so any rebuild is a different identity to the keychain.
    pub adhoc: bool,
    /// The designated requirement, as `codesign -d -r-` prints it. This is
    /// what an item created by this process names in its access list.
    pub requirement: String,
}

/// Describe this process's own code signature.
pub fn own_signature() -> Result<Signature, Error> {
    let mut code: CFTypeRef = std::ptr::null();
    // SAFETY: out-parameter; new reference released by `Cf`.
    let status = unsafe { SecCodeCopySelf(K_SEC_CS_DEFAULT_FLAGS, &mut code) };
    if status != 0 {
        return Err(os_error(status));
    }
    let code = Cf::new(code).ok_or_else(|| Error::Invalid("SecCodeCopySelf: null".into()))?;
    let mut static_code: CFTypeRef = std::ptr::null();
    // SAFETY: valid SecCodeRef; out-parameter.
    let status = unsafe { SecCodeCopyStaticCode(code.0, K_SEC_CS_DEFAULT_FLAGS, &mut static_code) };
    if status != 0 {
        return Err(os_error(status));
    }
    let static_code =
        Cf::new(static_code).ok_or_else(|| Error::Invalid("SecCodeCopyStaticCode: null".into()))?;

    let mut info: CFTypeRef = std::ptr::null();
    // SAFETY: valid SecStaticCodeRef; out-parameter.
    let status = unsafe {
        SecCodeCopySigningInformation(static_code.0, K_SEC_CS_SIGNING_INFORMATION, &mut info)
    };
    if status != 0 {
        return Err(os_error(status));
    }
    let info = Cf::new(info).ok_or_else(|| Error::Invalid("no signing information".into()))?;
    let mut flags: i64 = 0;
    // SAFETY: `info` is a valid dictionary; the value (if any) is a CFNumber
    // borrowed from it, read into an i64 out-parameter.
    unsafe {
        let value = CFDictionaryGetValue(info.0, kSecCodeInfoFlags);
        if !value.is_null() {
            CFNumberGetValue(
                value,
                K_CF_NUMBER_SINT64_TYPE,
                (&raw mut flags).cast::<c_void>(),
            );
        }
    }

    let mut requirement: CFTypeRef = std::ptr::null();
    // SAFETY: valid SecStaticCodeRef; out-parameter.
    let status = unsafe {
        SecCodeCopyDesignatedRequirement(static_code.0, K_SEC_CS_DEFAULT_FLAGS, &mut requirement)
    };
    let requirement = if status == 0 {
        Cf::new(requirement).and_then(|r| {
            let mut text: CFTypeRef = std::ptr::null();
            // SAFETY: valid SecRequirementRef; out-parameter.
            let status =
                unsafe { SecRequirementCopyString(r.0, K_SEC_CS_DEFAULT_FLAGS, &mut text) };
            if status != 0 {
                return None;
            }
            Cf::new(text).and_then(|t| string_from_cf(t.0))
        })
    } else {
        None
    };
    Ok(Signature {
        adhoc: flags & K_SEC_CODE_SIGNATURE_ADHOC != 0,
        requirement: requirement.unwrap_or_else(|| "(unsigned)".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A throwaway keychain file, deleted on drop. Tests never touch the
    /// login keychain: every item names this file explicitly.
    struct TempKeychain {
        dir: PathBuf,
        path: PathBuf,
    }

    const PASSWORD: &str = "spiceio-test-keychain";

    impl TempKeychain {
        fn new() -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "spiceio-keychain-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("test.keychain-db");
            security(&["create-keychain", "-p", PASSWORD, path.to_str().unwrap()]);
            // No auto-lock timeout: a slow CI host must not lock it mid-test.
            security(&["set-keychain-settings", path.to_str().unwrap()]);
            Self { dir, path }
        }

        fn item(&self, account: &str) -> Item {
            Item {
                service: "ai.spice.spiceio.test".into(),
                account: account.into(),
                keychain: Some(self.path.clone()),
            }
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
            .expect("run security");
        assert!(
            out.status.success(),
            "security {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn store_then_read_round_trips_bytes() {
        let kc = TempKeychain::new();
        let item = kc.item("smb://u@nas");
        let secret = "p@ss w0rd&<amp>\"\u{e9}".as_bytes();
        assert_eq!(store(&item, "test", secret), Ok(Stored::Added));
        assert_eq!(read(&item).unwrap(), secret);
    }

    #[test]
    fn store_reports_unchanged_then_updated() {
        let kc = TempKeychain::new();
        let item = kc.item("smb://u@nas");
        assert_eq!(store(&item, "test", b"one"), Ok(Stored::Added));
        assert_eq!(store(&item, "test", b"one"), Ok(Stored::Unchanged));
        assert_eq!(store(&item, "test", b"two"), Ok(Stored::Updated));
        assert_eq!(read(&item).unwrap(), b"two");
    }

    #[test]
    fn items_are_keyed_by_account() {
        let kc = TempKeychain::new();
        store(&kc.item("smb://u@nas"), "test", b"one").unwrap();
        assert_eq!(read(&kc.item("smb://u@elsewhere")), Err(Error::NotFound));
    }

    #[test]
    fn empty_secret_is_refused() {
        let kc = TempKeychain::new();
        assert!(matches!(
            store(&kc.item("smb://u@nas"), "test", b""),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn missing_keychain_file_is_named() {
        let item = Item {
            service: "s".into(),
            account: "a".into(),
            keychain: Some(std::env::temp_dir().join("spiceio-no-such.keychain-db")),
        };
        assert_eq!(read(&item), Err(Error::NoSuchKeychain));
    }

    #[test]
    fn locked_keychain_fails_without_prompting() {
        let kc = TempKeychain::new();
        let item = kc.item("smb://u@nas");
        store(&item, "test", b"one").unwrap();
        assert_eq!(keychain_unlocked(&kc.path), Ok(true));
        security(&["lock-keychain", kc.path.to_str().unwrap()]);
        assert_eq!(keychain_unlocked(&kc.path), Ok(false));
        assert_eq!(read(&item), Err(Error::Denied { locked: true }));
        // A write to an item that cannot be read is refused, not attempted.
        assert_eq!(
            store(&item, "test", b"two"),
            Err(Error::Denied { locked: true })
        );
        security(&["unlock-keychain", "-p", PASSWORD, kc.path.to_str().unwrap()]);
        assert_eq!(read(&item).unwrap(), b"one");
    }

    #[test]
    fn interaction_setting_is_restored() {
        let kc = TempKeychain::new();
        let _ = read(&kc.item("smb://u@nas"));
        let _guard = KEYCHAIN.lock().unwrap();
        let mut allowed: Boolean = 0;
        // SAFETY: out-parameter.
        unsafe { SecKeychainGetUserInteractionAllowed(&mut allowed) };
        assert_eq!(allowed, 1);
    }

    #[test]
    fn test_binary_is_adhoc_signed() {
        // cargo's linker signs ad-hoc; the keychain would pin its cdhash.
        let sig = own_signature().unwrap();
        assert!(sig.adhoc, "{sig:?}");
        assert!(sig.requirement.contains("cdhash"), "{sig:?}");
    }
}
