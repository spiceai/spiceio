//! Raw FFI bindings to macOS CommonCrypto.

use std::os::raw::{c_uint, c_void};

// CommonCrypto digest lengths
const CC_MD4_DIGEST_LENGTH: usize = 16;
const CC_MD5_DIGEST_LENGTH: usize = 16;
const CC_SHA256_DIGEST_LENGTH: usize = 32;
const CC_SHA512_DIGEST_LENGTH: usize = 64;

// HMAC algorithm identifiers (from CommonCrypto/CommonHMAC.h)
const K_CC_HMAC_ALG_MD5: c_uint = 1;
const K_CC_HMAC_ALG_SHA256: c_uint = 2;

// CCCrypt constants
const K_CC_ENCRYPT: u32 = 0;
const K_CC_ALGORITHM_AES128: u32 = 0;
const K_CC_OPTION_ECB_MODE: u32 = 2;

const AES_BLOCK_SIZE: usize = 16;

unsafe extern "C" {
    // CC_MD4
    fn CC_MD4(data: *const c_void, len: c_uint, md: *mut u8) -> *mut u8;

    // CC_MD5
    #[cfg(test)]
    fn CC_MD5(data: *const c_void, len: c_uint, md: *mut u8) -> *mut u8;

    // CC_SHA256
    fn CC_SHA256(data: *const c_void, len: c_uint, md: *mut u8) -> *mut u8;

    // CC_SHA512
    fn CC_SHA512(data: *const c_void, len: c_uint, md: *mut u8) -> *mut u8;

    // CCHmac
    fn CCHmac(
        algorithm: c_uint,
        key: *const c_void,
        key_length: usize,
        data: *const c_void,
        data_length: usize,
        mac_out: *mut c_void,
    );

    // CCCrypt — single-shot encrypt/decrypt
    fn CCCrypt(
        op: u32,
        alg: u32,
        options: u32,
        key: *const c_void,
        key_length: usize,
        iv: *const c_void,
        data_in: *const c_void,
        data_in_length: usize,
        data_out: *mut c_void,
        data_out_available: usize,
        data_out_moved: *mut usize,
    ) -> i32;
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

#[cfg(test)]
/// Compute MD5 digest. Used in tests for the CommonCrypto binding.
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

/// Compute SHA-512 digest. Used for SMB 3.1.1 preauth integrity hash.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; CC_SHA512_DIGEST_LENGTH];
    unsafe {
        CC_SHA512(
            data.as_ptr() as *const c_void,
            data.len() as c_uint,
            out.as_mut_ptr(),
        );
    }
    out
}

/// Compute HMAC-SHA256. Used in signing key derivation (SP800-108 KDF).
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

/// AES-ECB encrypt a single 16-byte block.
fn aes128_ecb_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut out_len: usize = 0;
    unsafe {
        CCCrypt(
            K_CC_ENCRYPT,
            K_CC_ALGORITHM_AES128,
            K_CC_OPTION_ECB_MODE,
            key.as_ptr() as *const c_void,
            16,
            std::ptr::null(),
            block.as_ptr() as *const c_void,
            16,
            out.as_mut_ptr() as *mut c_void,
            16,
            &mut out_len,
        );
    }
    out
}

/// Compute AES-128-CMAC (RFC 4493). Used for SMB 3.x message signing.
pub fn aes128_cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    // Step 1: Generate subkeys
    let zero_block = [0u8; AES_BLOCK_SIZE];
    let l = aes128_ecb_block(key, &zero_block);

    let k1 = dbl_block(&l);
    let k2 = dbl_block(&k1);

    // Step 2: Determine number of blocks
    let n = if data.is_empty() {
        1
    } else {
        (data.len() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE
    };
    let complete = !data.is_empty() && data.len() % AES_BLOCK_SIZE == 0;

    // Step 3: Build the last block
    let mut last = [0u8; AES_BLOCK_SIZE];
    if complete {
        let start = (n - 1) * AES_BLOCK_SIZE;
        last.copy_from_slice(&data[start..start + AES_BLOCK_SIZE]);
        xor_block(&mut last, &k1);
    } else {
        // Pad with 10*
        let start = (n - 1) * AES_BLOCK_SIZE;
        let remaining = data.len() - start;
        last[..remaining].copy_from_slice(&data[start..]);
        last[remaining] = 0x80;
        // rest is already zero
        xor_block(&mut last, &k2);
    }

    // Step 4: CBC-MAC
    let mut x = [0u8; AES_BLOCK_SIZE];
    for i in 0..n - 1 {
        let start = i * AES_BLOCK_SIZE;
        let mut block = [0u8; AES_BLOCK_SIZE];
        block.copy_from_slice(&data[start..start + AES_BLOCK_SIZE]);
        xor_block(&mut block, &x);
        x = aes128_ecb_block(key, &block);
    }
    xor_block(&mut last, &x);
    aes128_ecb_block(key, &last)
}

/// Double a block in GF(2^128) with the AES-CMAC polynomial.
fn dbl_block(block: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }
    if block[0] & 0x80 != 0 {
        out[15] ^= 0x87; // Rb for 128-bit block
    }
    out
}

/// XOR two 16-byte blocks in place.
fn xor_block(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
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
