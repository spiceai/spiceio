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
const K_CF_NUMBER_SINT32_TYPE: CFIndex = 3;
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
    static kCFBooleanFalse: CFTypeRef;
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
    fn CFNumberCreate(alloc: CFTypeRef, kind: CFIndex, value: *const c_void) -> CFTypeRef;
    fn CFErrorCopyDescription(error: CFTypeRef) -> CFTypeRef;
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
    static kSecAttrKeyType: CFTypeRef;
    static kSecAttrKeyTypeRSA: CFTypeRef;
    static kSecAttrKeySizeInBits: CFTypeRef;
    static kSecPrivateKeyAttrs: CFTypeRef;
    static kSecPublicKeyAttrs: CFTypeRef;
    static kSecAttrIsPermanent: CFTypeRef;
    static kSecAttrIsExtractable: CFTypeRef;
    static kSecAttrAccess: CFTypeRef;
    static kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256: CFTypeRef;
    static kSecClassCertificate: CFTypeRef;
    static kSecValueRef: CFTypeRef;

    fn SecKeyCreateRandomKey(parameters: CFTypeRef, error: *mut CFTypeRef) -> CFTypeRef;
    fn SecKeyCopyPublicKey(key: CFTypeRef) -> CFTypeRef;
    fn SecKeyCopyExternalRepresentation(key: CFTypeRef, error: *mut CFTypeRef) -> CFTypeRef;
    fn SecKeyCreateSignature(
        key: CFTypeRef,
        algorithm: CFTypeRef,
        data: CFTypeRef,
        error: *mut CFTypeRef,
    ) -> CFTypeRef;
    fn SecCertificateCreateWithData(alloc: CFTypeRef, data: CFTypeRef) -> CFTypeRef;
    fn SecAccessCreate(
        descriptor: CFTypeRef,
        trusted: CFTypeRef,
        access: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecTrustedApplicationCreateFromPath(path: *const c_char, app: *mut CFTypeRef) -> OSStatus;

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
    /// Wrap a Create/Copy result, or `None` for null. Lazily: a `Cf` built
    /// around null would `CFRelease(NULL)` on drop, which crashes.
    fn new(ptr: CFTypeRef) -> Option<Self> {
        if ptr.is_null() { None } else { Some(Self(ptr)) }
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

/// A CFArray of CF-type values (retained by the array).
fn cf_array(values: &[CFTypeRef]) -> Result<Cf, Error> {
    // SAFETY: `values` holds valid CF objects for the call; the CFType
    // callbacks retain them for the array's lifetime.
    let ptr = unsafe {
        CFArrayCreate(
            std::ptr::null(),
            values.as_ptr(),
            values.len() as CFIndex,
            &raw const kCFTypeArrayCallBacks,
        )
    };
    Cf::new(ptr).ok_or_else(|| Error::Invalid("CFArrayCreate failed".into()))
}

/// `path` as a C string, for the calls that take one.
fn c_path(path: &Path) -> Result<CString, Error> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::Invalid(format!("{} contains NUL", path.display())))
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
/// keychain file) or, when that is `None`, the login keychain. The login
/// keychain by path, not the user's search list or default keychain: any
/// process running as the user can put a keychain of its own first in that
/// list, and an item there would then be read (and, on a store, written)
/// instead of the real one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// `kSecAttrService`.
    pub service: String,
    /// `kSecAttrAccount`.
    pub account: String,
    /// A keychain file to use instead of the login keychain.
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

    /// The one keychain file every operation on this item names: the
    /// configured one, or the login keychain by path.
    pub fn file(&self) -> Result<PathBuf, Error> {
        match &self.keychain {
            Some(path) => Ok(path.clone()),
            None => login_keychain(),
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
    let c_path = c_path(path)?;
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

/// `struct passwd` from <pwd.h> (macOS layout).
#[repr(C)]
struct Passwd {
    pw_name: *mut c_char,
    pw_passwd: *mut c_char,
    pw_uid: u32,
    pw_gid: u32,
    pw_change: i64,
    pw_class: *mut c_char,
    pw_gecos: *mut c_char,
    pw_dir: *mut c_char,
    pw_shell: *mut c_char,
    pw_expire: i64,
}

unsafe extern "C" {
    fn getuid() -> u32;
    fn getpwuid_r(
        uid: u32,
        pwd: *mut Passwd,
        buf: *mut c_char,
        buflen: usize,
        result: *mut *mut Passwd,
    ) -> i32;
}

/// The home directory of the user this process runs as, from the user
/// database: not `$HOME`, which differs between environments (an installer's
/// shell and a launchd agent's plist) for the same user.
fn user_home() -> Option<PathBuf> {
    // SAFETY: `Passwd` is plain pointers and integers, valid when zeroed.
    let mut pwd: Passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as c_char; 16 * 1024];
    let mut result: *mut Passwd = std::ptr::null_mut();
    // SAFETY: `pwd` and `buf` outlive the call, which writes the strings
    // `pwd` points at into `buf` (sized by its length).
    let rc = unsafe { getpwuid_r(getuid(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: on success `pw_dir` is a NUL-terminated string inside `buf`.
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

/// The login keychain's file, `~/Library/Keychains/login.keychain-db`, with
/// `~` from the user database. So `make install` (checking from a shell) and
/// the launchd agent (reading at startup) resolve the same file whatever
/// `HOME` their environments carry.
pub fn login_keychain() -> Result<PathBuf, Error> {
    user_home()
        .map(|home| home.join("Library/Keychains/login.keychain-db"))
        .ok_or_else(|| {
            Error::Invalid("no home directory for this user, so no login keychain".into())
        })
}

/// The one keychain file an item addresses (see [`Item`]), opened, and the
/// one-element search list built from it, so every query and write is
/// confined to it. Both stay alive for as long as a query uses them.
struct Target {
    keychain: Cf,
    search_list: Cf,
}

impl Target {
    fn new(item: &Item) -> Result<Self, Error> {
        let keychain = open_keychain(&item.file()?)?;
        // A file that does not exist opens fine and only fails later with a
        // vaguer status; ask now so the error names the real problem.
        keychain_locked(keychain.0)?;
        let search_list = cf_array(&[keychain.0])?;
        Ok(Self {
            keychain,
            search_list,
        })
    }

    /// Map a refusal to [`Error::Denied`], with the lock state the status
    /// itself does not carry.
    fn classify(&self, status: OSStatus) -> Error {
        match status {
            ERR_SEC_ITEM_NOT_FOUND => Error::NotFound,
            ERR_SEC_NO_SUCH_KEYCHAIN => Error::NoSuchKeychain,
            ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED => Error::Denied {
                locked: keychain_locked(self.keychain.0).unwrap_or(false),
            },
            other => os_error(other),
        }
    }
}

/// The attributes that identify `item` in a query: class, service, account,
/// and the one-keychain search list.
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
            (kSecMatchSearchList, target.search_list.0),
        ]
    };
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

/// Read the secret of the item `keys` names. Caller holds a [`NoPrompts`].
fn read_unlocked(target: &Target, keys: &(Cf, Cf)) -> Result<Vec<u8>, Error> {
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
    data_bytes(&data)
}

/// Read `item`'s secret, without prompting.
pub fn read(item: &Item) -> Result<Vec<u8>, Error> {
    let _no_prompts = NoPrompts::new();
    let target = Target::new(item)?;
    let keys = item_keys(item)?;
    read_unlocked(&target, &keys)
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
    let outcome = match read_unlocked(&target, &keys) {
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
            let attributes = cf_dict(&unsafe {
                [
                    (kSecClass, kSecClassGenericPassword),
                    (kSecAttrService, keys.0.0),
                    (kSecAttrAccount, keys.1.0),
                    (kSecAttrLabel, label.0),
                    (kSecValueData, data.0),
                    (kSecUseKeychain, target.keychain.0),
                ]
            })?;
            // SAFETY: valid dictionary; no result requested.
            let status = unsafe { SecItemAdd(attributes.0, std::ptr::null_mut()) };
            if status != 0 {
                return Err(target.classify(status));
            }
            Stored::Added
        }
        Err(e) => return Err(e),
    };
    match read_unlocked(&target, &keys) {
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

// ── Signing identity ─────────────────────────────────────────────────────

/// The access list a key's ACL is built from: the given applications, plus
/// this binary (it signs the key's own certificate right after creating it).
fn access_for(label: &str, trusted_apps: &[&Path]) -> Result<Cf, Error> {
    let paths = trusted_apps
        .iter()
        .map(|path| c_path(path).map(Some))
        .collect::<Result<Vec<_>, _>>()?;
    let mut apps: Vec<Cf> = Vec::with_capacity(paths.len() + 1);
    // `None` first: a null path is "this application".
    for path in std::iter::once(None).chain(paths) {
        let mut app: CFTypeRef = std::ptr::null();
        let ptr = path.as_ref().map_or(std::ptr::null(), |p| p.as_ptr());
        // SAFETY: null or a NUL-terminated path; out-parameter.
        let status = unsafe { SecTrustedApplicationCreateFromPath(ptr, &mut app) };
        if status != 0 {
            return Err(os_error(status));
        }
        apps.push(Cf::new(app).ok_or_else(|| Error::Invalid("no trusted application".into()))?);
    }
    let list = cf_array(&apps.iter().map(|a| a.0).collect::<Vec<_>>())?;
    let descriptor = cf_string(label)?;
    let mut access: CFTypeRef = std::ptr::null();
    // SAFETY: valid CFString and CFArray; out-parameter.
    let status = unsafe { SecAccessCreate(descriptor.0, list.0, &mut access) };
    if status != 0 {
        return Err(os_error(status));
    }
    Cf::new(access).ok_or_else(|| Error::Invalid("SecAccessCreate returned null".into()))
}

/// The description a Security.framework `CFErrorRef` carries (and releases it).
fn cf_error(error: CFTypeRef, what: &str) -> Error {
    let Some(error) = Cf::new(error) else {
        return Error::Invalid(format!("{what} failed"));
    };
    // SAFETY: a valid CFError; returns a new CFString or null.
    let text =
        Cf::new(unsafe { CFErrorCopyDescription(error.0) }).and_then(|t| string_from_cf(t.0));
    Error::Invalid(format!(
        "{what}: {}",
        text.unwrap_or_else(|| "unknown error".into())
    ))
}

/// Create a code-signing identity inside the keychain file `keychain`: an
/// RSA-3072 key pair generated *in* the keychain, whose private key is
/// non-extractable from the moment it exists, and a self-signed certificate
/// for it (code signing, `valid_days` long), signed in this process with that
/// key. The private key is never written anywhere, so no copy of it can
/// exist. Its access list names `trusted_apps` (e.g. `/usr/bin/codesign`)
/// and this binary, which needs it once, to sign the certificate.
///
/// `scripts/codesign-local.sh` runs this through `spiceio
/// --create-signing-identity`. The keychain must be unlocked.
pub fn create_signing_identity(
    keychain: &Path,
    common_name: &str,
    trusted_apps: &[&Path],
    valid_days: u32,
) -> Result<(), Error> {
    if common_name.is_empty() {
        return Err(Error::Invalid("the identity needs a common name".into()));
    }
    let _no_prompts = NoPrompts::new();
    let kc = open_keychain(keychain)?;
    if keychain_locked(kc.0)? {
        return Err(Error::Denied { locked: true });
    }
    let access = access_for(common_name, trusted_apps)?;
    let label = cf_string(common_name)?;
    let bits: i32 = 3072;
    // SAFETY: the value outlives the call; CF copies it.
    let size = Cf::new(unsafe {
        CFNumberCreate(
            std::ptr::null(),
            K_CF_NUMBER_SINT32_TYPE,
            (&raw const bits).cast::<c_void>(),
        )
    })
    .ok_or_else(|| Error::Invalid("CFNumberCreate failed".into()))?;
    // SAFETY: reading immutable framework constants.
    let private_attrs = cf_dict(&unsafe {
        [
            (kSecAttrIsPermanent, kCFBooleanTrue),
            (kSecAttrLabel, label.0),
        ]
    })?;
    // The certificate carries the public key; the keychain needs only the
    // private half for the identity.
    // SAFETY: reading immutable framework constants.
    let public_attrs = cf_dict(&unsafe { [(kSecAttrIsPermanent, kCFBooleanFalse)] })?;
    // SAFETY: reading immutable framework constants.
    let params = cf_dict(&unsafe {
        [
            (kSecAttrKeyType, kSecAttrKeyTypeRSA),
            (kSecAttrKeySizeInBits, size.0),
            (kSecUseKeychain, kc.0),
            (kSecPrivateKeyAttrs, private_attrs.0),
            (kSecPublicKeyAttrs, public_attrs.0),
            // Both at the top level, not in kSecPrivateKeyAttrs: measured on
            // macOS 27.2.1, a file keychain's key ignores them there. It came
            // out Extractable=1, and with only its creator on its ACL, so
            // codesign was refused (errSecInternalComponent, and a dialog).
            // Here it is Extractable=0, NeverExtractable=1, and the ACL lists
            // this binary and /usr/bin/codesign.
            (kSecAttrIsExtractable, kCFBooleanFalse),
            (kSecAttrAccess, access.0),
        ]
    })?;
    let mut error: CFTypeRef = std::ptr::null();
    // SAFETY: valid parameters dictionary; out-parameter for the error.
    let private_key = Cf::new(unsafe { SecKeyCreateRandomKey(params.0, &mut error) })
        .ok_or_else(|| cf_error(error, "generating the key pair"))?;
    // SAFETY: a valid SecKeyRef; returns a new reference or null.
    let public_key = Cf::new(unsafe { SecKeyCopyPublicKey(private_key.0) })
        .ok_or_else(|| Error::Invalid("the new key has no public half".into()))?;
    let mut error: CFTypeRef = std::ptr::null();
    // SAFETY: a valid SecKeyRef; out-parameter for the error.
    let public_der = Cf::new(unsafe { SecKeyCopyExternalRepresentation(public_key.0, &mut error) })
        .ok_or_else(|| cf_error(error, "exporting the public key"))?;
    let public_der = data_bytes(&public_der)?;

    let mut serial = crate::crypto::random_bytes::<16>();
    // Positive (high bit clear) and never shortened by leading zeros.
    serial[0] = (serial[0] & 0x7f) | 0x40;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Invalid("the clock is before 1970".into()))?
        .as_secs() as i64;
    let not_before = now - 60;
    let not_after = now + i64::from(valid_days) * 86_400;
    let tbs = x509::tbs_certificate(common_name, &serial, not_before, not_after, &public_der);

    let tbs_data = cf_data(&tbs)?;
    let mut error: CFTypeRef = std::ptr::null();
    // SAFETY: valid key, algorithm constant and data; out-parameter.
    let signature = Cf::new(unsafe {
        SecKeyCreateSignature(
            private_key.0,
            kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
            tbs_data.0,
            &mut error,
        )
    })
    .ok_or_else(|| cf_error(error, "signing the certificate"))?;
    let certificate = x509::certificate(&tbs, &data_bytes(&signature)?);

    let cert_data = cf_data(&certificate)?;
    // SAFETY: valid CFData; returns a new SecCertificateRef or null.
    let cert = Cf::new(unsafe { SecCertificateCreateWithData(std::ptr::null(), cert_data.0) })
        .ok_or_else(|| Error::Invalid("the generated certificate does not parse".into()))?;
    // SAFETY: reading immutable framework constants.
    let add = cf_dict(&unsafe {
        [
            (kSecClass, kSecClassCertificate),
            (kSecValueRef, cert.0),
            (kSecUseKeychain, kc.0),
        ]
    })?;
    // SAFETY: valid dictionary; no result requested.
    let status = unsafe { SecItemAdd(add.0, std::ptr::null_mut()) };
    if status != 0 {
        return Err(os_error(status));
    }
    Ok(())
}

/// The bytes of a CFData.
fn data_bytes(data: &Cf) -> Result<Vec<u8>, Error> {
    // SAFETY: `data` is a valid CF object; its type is checked first and the
    // bytes are copied while it is alive.
    unsafe {
        if CFGetTypeID(data.0) != CFDataGetTypeID() {
            return Err(Error::Invalid("expected data".into()));
        }
        let len = usize::try_from(CFDataGetLength(data.0)).unwrap_or(0);
        let ptr = CFDataGetBytePtr(data.0);
        if len == 0 || ptr.is_null() {
            return Ok(Vec::new());
        }
        Ok(std::slice::from_raw_parts(ptr, len).to_vec())
    }
}

/// Just enough DER to write one self-signed X.509 v3 code-signing
/// certificate. No parser: Security.framework parses the result
/// (`SecCertificateCreateWithData`), and codesign checks it.
mod x509 {
    pub(super) fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let bytes: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|&b| b == 0)
                .collect();
            out.push(0x80 | bytes.len() as u8);
            out.extend_from_slice(&bytes);
        }
        out.extend_from_slice(content);
        out
    }

    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &parts.concat())
    }

    fn oid(arcs: &[u64]) -> Vec<u8> {
        let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
        for &arc in &arcs[2..] {
            let mut chunk = vec![(arc & 0x7f) as u8];
            let mut rest = arc >> 7;
            while rest > 0 {
                chunk.push(0x80 | (rest & 0x7f) as u8);
                rest >>= 7;
            }
            chunk.reverse();
            body.extend_from_slice(&chunk);
        }
        der(0x06, &body)
    }

    fn integer(bytes: &[u8]) -> Vec<u8> {
        let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|&b| b == 0).collect();
        let mut body = if trimmed.is_empty() { vec![0] } else { trimmed };
        if body[0] & 0x80 != 0 {
            body.insert(0, 0);
        }
        der(0x02, &body)
    }

    fn bit_string(bytes: &[u8]) -> Vec<u8> {
        let mut body = vec![0];
        body.extend_from_slice(bytes);
        der(0x03, &body)
    }

    const NULL: [u8; 2] = [0x05, 0x00];
    const TRUE: [u8; 3] = [0x01, 0x01, 0xff];

    fn name(common_name: &str) -> Vec<u8> {
        let attribute = seq(&[oid(&[2, 5, 4, 3]), der(0x0c, common_name.as_bytes())]);
        seq(&[der(0x31, &attribute)])
    }

    /// The civil date of `days` since 1970-01-01 (proleptic Gregorian).
    pub(super) fn civil_from_days(days: i64) -> (i64, u32, u32) {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let year = yoe + era * 400 + i64::from(month <= 2);
        (year, month, day)
    }

    /// UTCTime before 2050, GeneralizedTime from then on (RFC 5280 4.1.2.5).
    pub(super) fn time(unix: i64) -> Vec<u8> {
        let (year, month, day) = civil_from_days(unix.div_euclid(86_400));
        let secs = unix.rem_euclid(86_400);
        let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
        if (1950..2050).contains(&year) {
            let text = format!("{:02}{month:02}{day:02}{h:02}{m:02}{s:02}Z", year % 100);
            der(0x17, text.as_bytes())
        } else {
            let text = format!("{year:04}{month:02}{day:02}{h:02}{m:02}{s:02}Z");
            der(0x18, text.as_bytes())
        }
    }

    fn sha256_with_rsa() -> Vec<u8> {
        seq(&[oid(&[1, 2, 840, 113_549, 1, 1, 11]), NULL.to_vec()])
    }

    /// `pkcs1_public_key`: what `SecKeyCopyExternalRepresentation` returns
    /// for an RSA public key (a PKCS#1 RSAPublicKey).
    pub(super) fn tbs_certificate(
        common_name: &str,
        serial: &[u8],
        not_before: i64,
        not_after: i64,
        pkcs1_public_key: &[u8],
    ) -> Vec<u8> {
        let spki = seq(&[
            seq(&[oid(&[1, 2, 840, 113_549, 1, 1, 1]), NULL.to_vec()]),
            bit_string(pkcs1_public_key),
        ]);
        let basic_constraints = seq(&[oid(&[2, 5, 29, 19]), TRUE.to_vec(), der(0x04, &seq(&[]))]);
        // digitalSignature: bit 0 of a one-byte BIT STRING with 7 unused bits.
        let key_usage = seq(&[
            oid(&[2, 5, 29, 15]),
            TRUE.to_vec(),
            der(0x04, &der(0x03, &[0x07, 0x80])),
        ]);
        let ext_key_usage = seq(&[
            oid(&[2, 5, 29, 37]),
            TRUE.to_vec(),
            der(0x04, &seq(&[oid(&[1, 3, 6, 1, 5, 5, 7, 3, 3])])),
        ]);
        seq(&[
            der(0xa0, &integer(&[2])),
            integer(serial),
            sha256_with_rsa(),
            name(common_name),
            seq(&[time(not_before), time(not_after)]),
            name(common_name),
            spki,
            der(0xa3, &seq(&[basic_constraints, key_usage, ext_key_usage])),
        ])
    }

    pub(super) fn certificate(tbs: &[u8], signature: &[u8]) -> Vec<u8> {
        seq(&[tbs.to_vec(), sha256_with_rsa(), bit_string(signature)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// A throwaway keychain file, deleted on drop. Tests never touch the
    /// login keychain: every item names this file explicitly.
    struct TempKeychain {
        path: PathBuf,
        // Dropped after `Drop::drop` has deleted the keychain.
        _dir: crate::test_support::TempDir,
    }

    const PASSWORD: &str = "spiceio-test-keychain";

    impl TempKeychain {
        fn new() -> Self {
            let dir = crate::test_support::TempDir::new("keychain");
            let path = dir.0.join("test.keychain-db");
            security(&["create-keychain", "-p", PASSWORD, path.to_str().unwrap()]);
            // No auto-lock timeout: a slow CI host must not lock it mid-test.
            security(&["set-keychain-settings", path.to_str().unwrap()]);
            Self { path, _dir: dir }
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

    /// The length a DER encoding claims.
    fn der_length(encoded: &[u8]) -> usize {
        let first = encoded[1];
        if first < 0x80 {
            usize::from(first)
        } else {
            encoded[2..2 + usize::from(first & 0x7f)]
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b))
        }
    }

    #[test]
    fn der_lengths_round_trip() {
        for len in [0usize, 1, 127, 128, 255, 256, 65_535, 65_536] {
            let encoded = x509::der(0x04, &vec![0u8; len]);
            assert_eq!(der_length(&encoded), len, "length {len}");
        }
    }

    #[test]
    fn civil_dates_and_times() {
        assert_eq!(x509::civil_from_days(0), (1970, 1, 1));
        assert_eq!(x509::civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(x509::civil_from_days(11_016), (2000, 2, 29));
        // 2026-11-21T20:30:00Z: UTCTime.
        assert_eq!(&x509::time(1_795_293_000)[2..], b"261121203000Z");
        assert_eq!(x509::time(1_795_293_000)[0], 0x17);
        // 2050 and later: GeneralizedTime.
        let t = x509::time(2_524_608_000); // 2050-01-01T00:00:00Z
        assert_eq!((t[0], &t[2..]), (0x18, &b"20500101000000Z"[..]));
    }

    #[test]
    fn signing_identity_is_born_non_extractable_in_the_keychain() {
        let kc = TempKeychain::new();
        create_signing_identity(
            &kc.path,
            "spiceio test signing",
            &[Path::new("/usr/bin/codesign")],
            30,
        )
        .unwrap();
        let out = Command::new("/usr/bin/security")
            .args([
                "find-identity",
                "-p",
                "codesigning",
                kc.path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        let listing = String::from_utf8_lossy(&out.stdout);
        assert!(
            listing.contains("\"spiceio test signing\""),
            "no identity in the keychain:\n{listing}"
        );
        // Attribute 0x10 (Extractable) of the private key, read without -d:
        // attributes only, so no ACL check and no dialog.
        let dump = Command::new("/usr/bin/security")
            .args(["dump-keychain", kc.path.to_str().unwrap()])
            .output()
            .unwrap();
        let dump = String::from_utf8_lossy(&dump.stdout);
        let private_key = dump
            .split("keychain: ")
            .find(|item| item.contains("class: 0x00000010"))
            .expect("a private key item");
        assert!(
            private_key.contains("0x00000010 <uint32>=0x00000000"),
            "the private key is extractable:\n{private_key}"
        );
        assert!(private_key.contains("0x00000011 <uint32>=0x00000001"));
        // codesign is on the key's access list (dump-keychain -a reads ACLs,
        // not the key), or it would be refused and raise a dialog.
        let acl = Command::new("/usr/bin/security")
            .args(["dump-keychain", "-a", kc.path.to_str().unwrap()])
            .output()
            .unwrap();
        let acl = String::from_utf8_lossy(&acl.stdout);
        let key_acl = acl
            .split("keychain: ")
            .find(|item| item.contains("class: 0x00000010"))
            .expect("a private key item");
        assert!(
            key_acl.contains("/usr/bin/codesign (OK)"),
            "codesign is not on the private key's access list:\n{key_acl}"
        );
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
