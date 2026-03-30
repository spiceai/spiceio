//! Raw FFI bindings to macOS CommonCrypto.

use std::os::raw::{c_uint, c_void};

// CommonCrypto digest lengths
const CC_MD4_DIGEST_LENGTH: usize = 16;
const CC_MD5_DIGEST_LENGTH: usize = 16;
const CC_SHA256_DIGEST_LENGTH: usize = 32;

// HMAC algorithm identifiers (from CommonCrypto/CommonHMAC.h)
const K_CC_HMAC_ALG_MD5: c_uint = 1;
const K_CC_HMAC_ALG_SHA256: c_uint = 2;

unsafe extern "C" {
    // CC_MD4
    fn CC_MD4(data: *const c_void, len: c_uint, md: *mut u8) -> *mut u8;

    // CC_MD5
    fn CC_MD5(data: *const c_void, len: c_uint, md: *mut u8) -> *mut u8;

    // CC_SHA256
    fn CC_SHA256(data: *const c_void, len: c_uint, md: *mut u8) -> *mut u8;

    // CCHmac
    fn CCHmac(
        algorithm: c_uint,
        key: *const c_void,
        key_length: usize,
        data: *const c_void,
        data_length: usize,
        mac_out: *mut c_void,
    );
}

/// Compute MD4 digest. Used in NTLM password hashing.
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; CC_MD4_DIGEST_LENGTH];
    unsafe {
        CC_MD4(
            data.as_ptr() as *const c_void,
            data.len() as c_uint,
            out.as_mut_ptr(),
        );
    }
    out
}

/// Compute MD5 digest. Used in NTLMv2 computations.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; CC_MD5_DIGEST_LENGTH];
    unsafe {
        CC_MD5(
            data.as_ptr() as *const c_void,
            data.len() as c_uint,
            out.as_mut_ptr(),
        );
    }
    out
}

/// Compute HMAC-MD5. Core of NTLMv2 authentication.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; CC_MD5_DIGEST_LENGTH];
    unsafe {
        CCHmac(
            K_CC_HMAC_ALG_MD5,
            key.as_ptr() as *const c_void,
            key.len(),
            data.as_ptr() as *const c_void,
            data.len(),
            out.as_mut_ptr() as *mut c_void,
        );
    }
    out
}

/// Compute SHA-256 digest. Used in AWS Signature V4.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; CC_SHA256_DIGEST_LENGTH];
    unsafe {
        CC_SHA256(
            data.as_ptr() as *const c_void,
            data.len() as c_uint,
            out.as_mut_ptr(),
        );
    }
    out
}

/// Compute HMAC-SHA256. Used in AWS Signature V4.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; CC_SHA256_DIGEST_LENGTH];
    unsafe {
        CCHmac(
            K_CC_HMAC_ALG_SHA256,
            key.as_ptr() as *const c_void,
            key.len(),
            data.as_ptr() as *const c_void,
            data.len(),
            out.as_mut_ptr() as *mut c_void,
        );
    }
    out
}

/// Encode bytes as lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_empty() {
        let digest = md5(b"");
        let expected: [u8; 16] = [
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
            0x42, 0x7e,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_md4_empty() {
        let digest = md4(b"");
        let expected: [u8; 16] = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0,
            0x89, 0xc0,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_hmac_md5() {
        // RFC 2104 test vector 1
        let key = [0x0b_u8; 16];
        let data = b"Hi There";
        let mac = hmac_md5(&key, data);
        let expected: [u8; 16] = [
            0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b,
            0xfc, 0x9d,
        ];
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_sha256_empty() {
        let digest = sha256(b"");
        assert_eq!(
            hex_encode(&digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hmac_sha256() {
        // RFC 4231 test case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac_sha256(key, data);
        assert_eq!(
            hex_encode(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
