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
/// Neither the ECB bit nor the PKCS7-padding bit: CBC with no padding.
const K_CC_OPTION_CBC_NO_PADDING: u32 = 0;
const K_CC_SUCCESS: i32 = 0;

const AES_BLOCK_SIZE: usize = 16;

/// Opaque CommonCrypto SHA-256 streaming context (`CC_SHA256_CTX`):
/// `count[2] + hash[8] + wbuf[16]` 32-bit words. Declared with `u32` fields so
/// the layout/alignment matches the C struct exactly.
#[repr(C)]
struct CcSha256Ctx {
    count: [u32; 2],
    hash: [u32; 8],
    wbuf: [u32; 16],
}

unsafe extern "C" {
    // CC_MD4
    fn CC_MD4(data: *const c_void, len: c_uint, md: *mut u8) -> *mut u8;

    // CC_MD5
    #[cfg(test)]
    fn CC_MD5(data: *const c_void, len: c_uint, md: *mut u8) -> *mut u8;

    // CC_SHA256 streaming API — used for inputs that may exceed u32 bytes.
    fn CC_SHA256_Init(ctx: *mut CcSha256Ctx) -> i32;
    fn CC_SHA256_Update(ctx: *mut CcSha256Ctx, data: *const c_void, len: c_uint) -> i32;
    fn CC_SHA256_Final(md: *mut u8, ctx: *mut CcSha256Ctx) -> i32;

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

    // CCCryptor — streaming encrypt. One key schedule for a whole message,
    // instead of one per block through the single-shot API.
    fn CCCryptorCreate(
        op: u32,
        alg: u32,
        options: u32,
        key: *const c_void,
        key_length: usize,
        iv: *const c_void,
        cryptor_ref: *mut CcCryptorRef,
    ) -> i32;
    fn CCCryptorUpdate(
        cryptor_ref: CcCryptorRef,
        data_in: *const c_void,
        data_in_length: usize,
        data_out: *mut c_void,
        data_out_available: usize,
        data_out_moved: *mut usize,
    ) -> i32;
    fn CCCryptorRelease(cryptor_ref: CcCryptorRef) -> i32;

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

/// Compute MD4 digest. Used in NTLM password hashing (always small inputs).
pub fn md4(data: &[u8]) -> [u8; 16] {
    // CommonCrypto takes a 32-bit length; callers only ever pass small buffers.
    debug_assert!(data.len() <= u32::MAX as usize, "md4 input exceeds u32");
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

/// Incremental SHA-256 hasher (CommonCrypto streaming API).
///
/// `update` chunks its input so the 32-bit length CommonCrypto expects is never
/// exceeded — correct for inputs larger than 4 GiB (e.g. a 5 GiB UploadPart),
/// which the one-shot `sha256` could otherwise silently truncate. Also lets
/// callers hash a body incrementally while streaming it, without buffering.
pub struct Sha256 {
    ctx: CcSha256Ctx,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        let mut ctx = CcSha256Ctx {
            count: [0; 2],
            hash: [0; 8],
            wbuf: [0; 16],
        };
        unsafe {
            CC_SHA256_Init(&mut ctx);
        }
        Self { ctx }
    }

    pub fn update(&mut self, data: &[u8]) {
        // Feed in <= u32::MAX slices so the length cast never truncates.
        const MAX: usize = u32::MAX as usize;
        let mut rest = data;
        while !rest.is_empty() {
            let n = rest.len().min(MAX);
            unsafe {
                CC_SHA256_Update(&mut self.ctx, rest.as_ptr() as *const c_void, n as c_uint);
            }
            rest = &rest[n..];
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let mut out = [0u8; CC_SHA256_DIGEST_LENGTH];
        unsafe {
            CC_SHA256_Final(out.as_mut_ptr(), &mut self.ctx);
        }
        out
    }
}

/// Compute SHA-256 digest. Used for ETags and AWS Signature V4. Handles inputs
/// of any size (chunks internally via the streaming API).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// Compute SHA-512 digest. Used for SMB 3.1.1 preauth integrity hash (bounded
/// by the 16 MiB SMB message cap, so always within u32).
pub fn sha512(data: &[u8]) -> [u8; 64] {
    debug_assert!(data.len() <= u32::MAX as usize, "sha512 input exceeds u32");
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

/// Opaque `CCCryptorRef`.
type CcCryptorRef = *mut c_void;

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

/// How much ciphertext the CBC-MAC pass asks CommonCrypto to write at a time.
/// Only the final block is the MAC, so everything else is discarded — this
/// just bounds the scratch buffer. A multiple of the AES block size, so every
/// update is block-aligned and CommonCrypto never buffers a partial block.
const CMAC_CHUNK: usize = 4096;

/// One-shot log if the streaming path ever fails, so the resulting ~10x
/// slowdown is visible rather than silent.
static CMAC_FALLBACK_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// CBC-MAC `head` (a whole number of AES blocks) followed by `last`, with a
/// zero IV, returning the final ciphertext block.
///
/// This is the whole trick behind CMAC's speed. The textbook loop
/// `x = AES(key, x ^ M_i)` *is* CBC mode, so one streaming CBC pass replaces a
/// per-block trip through the single-shot API — and each of those trips
/// re-expands the AES-128 key schedule, which costs far more than the 16 bytes
/// of AES it performs. Signing a 256 KiB SMB write is 16,384 blocks, so that
/// overhead is the difference between ~106 MiB/s and the hardware's speed.
///
/// Returns `None` if CommonCrypto refuses the operation, so the caller falls
/// back to the per-block path rather than returning a wrong MAC.
fn cbc_mac(key: &[u8; 16], head: &[u8], last: &[u8; 16]) -> Option<[u8; 16]> {
    debug_assert!(head.len().is_multiple_of(AES_BLOCK_SIZE));
    let iv = [0u8; AES_BLOCK_SIZE];
    let mut cryptor: CcCryptorRef = std::ptr::null_mut();
    // SAFETY: `key` and `iv` are the 16 bytes AES-128-CBC expects, and
    // `cryptor` is an out-parameter released on every path below.
    let status = unsafe {
        CCCryptorCreate(
            K_CC_ENCRYPT,
            K_CC_ALGORITHM_AES128,
            K_CC_OPTION_CBC_NO_PADDING,
            key.as_ptr() as *const c_void,
            AES_BLOCK_SIZE,
            iv.as_ptr() as *const c_void,
            &mut cryptor,
        )
    };
    if status != K_CC_SUCCESS || cryptor.is_null() {
        return None;
    }

    let mut scratch = [0u8; CMAC_CHUNK];
    let mut moved = 0usize;
    let mut ok = true;
    for chunk in head.chunks(CMAC_CHUNK) {
        // SAFETY: `chunk` is block-aligned and `scratch` is at least as large,
        // which is what CBC-without-padding needs to emit its ciphertext.
        let s = unsafe {
            CCCryptorUpdate(
                cryptor,
                chunk.as_ptr() as *const c_void,
                chunk.len(),
                scratch.as_mut_ptr() as *mut c_void,
                scratch.len(),
                &mut moved,
            )
        };
        if s != K_CC_SUCCESS {
            ok = false;
            break;
        }
    }

    let mut mac = [0u8; AES_BLOCK_SIZE];
    if ok {
        // The last block's ciphertext is the MAC.
        // SAFETY: one block in, one block of space out.
        let s = unsafe {
            CCCryptorUpdate(
                cryptor,
                last.as_ptr() as *const c_void,
                AES_BLOCK_SIZE,
                mac.as_mut_ptr() as *mut c_void,
                AES_BLOCK_SIZE,
                &mut moved,
            )
        };
        ok = s == K_CC_SUCCESS && moved == AES_BLOCK_SIZE;
    }

    // SAFETY: `cryptor` came from a successful create and is not used after.
    unsafe { CCCryptorRelease(cryptor) };
    ok.then_some(mac)
}

/// Compute AES-128-CMAC (RFC 4493). Used for SMB 3.x message signing.
pub fn aes128_cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    aes128_cmac_parts(key, &[data])
}

/// AES-128-CMAC over a concatenation of slices without allocating a contiguous
/// buffer. Used to sign SMB WRITE packets as `header || payload` so the write
/// path does not memcpy the data into the signed frame.
pub fn aes128_cmac_parts(key: &[u8; 16], parts: &[&[u8]]) -> [u8; 16] {
    let total: usize = parts.iter().map(|p| p.len()).sum();

    // Step 1: Generate subkeys
    let zero_block = [0u8; AES_BLOCK_SIZE];
    let l = aes128_ecb_block(key, &zero_block);

    let k1 = dbl_block(&l);
    let k2 = dbl_block(&k1);

    // Step 2: Determine number of blocks
    let n = if total == 0 {
        1
    } else {
        total.div_ceil(AES_BLOCK_SIZE)
    };
    let complete = total > 0 && total.is_multiple_of(AES_BLOCK_SIZE);

    // Step 3: Build the last block from the logical concatenation of `parts`.
    let mut last = [0u8; AES_BLOCK_SIZE];
    let last_start = (n - 1) * AES_BLOCK_SIZE;
    if complete {
        copy_parts_range(parts, last_start, &mut last);
        xor_block(&mut last, &k1);
    } else {
        let remaining = total.saturating_sub(last_start);
        if remaining > 0 {
            copy_parts_range(parts, last_start, &mut last[..remaining]);
        }
        last[remaining] = 0x80;
        xor_block(&mut last, &k2);
    }

    // Step 4: CBC-MAC every block but the last, then the tweaked last block.
    // Prefer a contiguous head when the message is a single slice (the common
    // non-WRITE path) so we keep the fast CommonCrypto CBC pass.
    let head_len = (n - 1) * AES_BLOCK_SIZE;
    if parts.len() == 1 {
        let head = &parts[0][..head_len];
        if let Some(mac) = cbc_mac(key, head, &last) {
            return mac;
        }
    } else if let Some(mac) = cbc_mac_parts(key, parts, head_len, &last) {
        return mac;
    }

    // Fallback: the same computation block by block. Correct but ~10x slower,
    // so it is announced once rather than degrading silently.
    if !CMAC_FALLBACK_LOGGED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        crate::serr!("[spiceio] AES-CMAC streaming path unavailable; signing will be slow");
    }
    let mut x = [0u8; AES_BLOCK_SIZE];
    let mut block = [0u8; AES_BLOCK_SIZE];
    for i in 0..n - 1 {
        copy_parts_range(parts, i * AES_BLOCK_SIZE, &mut block);
        for j in 0..AES_BLOCK_SIZE {
            x[j] ^= block[j];
        }
        x = aes128_ecb_block(key, &x);
    }
    xor_block(&mut last, &x);
    aes128_ecb_block(key, &last)
}

/// Copy `dst.len()` bytes starting at logical offset `start` across `parts`.
fn copy_parts_range(parts: &[&[u8]], mut start: usize, dst: &mut [u8]) {
    let mut out = 0usize;
    for part in parts {
        if start >= part.len() {
            start -= part.len();
            continue;
        }
        let take = (part.len() - start).min(dst.len() - out);
        dst[out..out + take].copy_from_slice(&part[start..start + take]);
        out += take;
        start = 0;
        if out == dst.len() {
            return;
        }
    }
    debug_assert_eq!(out, dst.len(), "copy_parts_range: short input");
}

/// CBC-MAC over a multi-slice head (whole number of AES blocks) + last block.
fn cbc_mac_parts(
    key: &[u8; 16],
    parts: &[&[u8]],
    head_len: usize,
    last: &[u8; 16],
) -> Option<[u8; 16]> {
    debug_assert!(head_len.is_multiple_of(AES_BLOCK_SIZE));
    let iv = [0u8; AES_BLOCK_SIZE];
    let mut cryptor: CcCryptorRef = std::ptr::null_mut();
    let status = unsafe {
        CCCryptorCreate(
            K_CC_ENCRYPT,
            K_CC_ALGORITHM_AES128,
            K_CC_OPTION_CBC_NO_PADDING,
            key.as_ptr() as *const c_void,
            AES_BLOCK_SIZE,
            iv.as_ptr() as *const c_void,
            &mut cryptor,
        )
    };
    if status != K_CC_SUCCESS || cryptor.is_null() {
        return None;
    }

    let mut scratch = [0u8; CMAC_CHUNK];
    let mut moved = 0usize;
    let mut ok = true;
    let mut remaining = head_len;
    let mut part_idx = 0usize;
    let mut part_off = 0usize;
    // Feed head bytes in block-aligned chunks from the slice stream. CommonCrypto
    // accepts any multiple of the block size per Update; we pack into `scratch`
    // only when a part boundary splits a chunk mid-way.
    let mut pack = [0u8; CMAC_CHUNK];
    let mut pack_len = 0usize;
    while remaining > 0 && ok {
        while part_idx < parts.len() && part_off >= parts[part_idx].len() {
            part_idx += 1;
            part_off = 0;
        }
        if part_idx >= parts.len() {
            ok = false;
            break;
        }
        let part = parts[part_idx];
        let avail = (part.len() - part_off).min(remaining);
        // Fast path: emit a full CMAC_CHUNK (or the remaining head) directly
        // when this part can supply it and the pack buffer is empty.
        if pack_len == 0 && avail >= AES_BLOCK_SIZE {
            let take = avail.min(CMAC_CHUNK);
            let take = take - (take % AES_BLOCK_SIZE); // block-align
            if take > 0 {
                let s = unsafe {
                    CCCryptorUpdate(
                        cryptor,
                        part[part_off..].as_ptr() as *const c_void,
                        take,
                        scratch.as_mut_ptr() as *mut c_void,
                        scratch.len(),
                        &mut moved,
                    )
                };
                if s != K_CC_SUCCESS {
                    ok = false;
                    break;
                }
                part_off += take;
                remaining -= take;
                continue;
            }
        }
        // Pack across a part boundary into `pack` until we have a full chunk
        // or have finished the head.
        let room = (CMAC_CHUNK - pack_len).min(remaining);
        let take = avail.min(room);
        pack[pack_len..pack_len + take].copy_from_slice(&part[part_off..part_off + take]);
        pack_len += take;
        part_off += take;
        remaining -= take;
        if pack_len == CMAC_CHUNK || remaining == 0 {
            debug_assert!(pack_len.is_multiple_of(AES_BLOCK_SIZE));
            let s = unsafe {
                CCCryptorUpdate(
                    cryptor,
                    pack.as_ptr() as *const c_void,
                    pack_len,
                    scratch.as_mut_ptr() as *mut c_void,
                    scratch.len(),
                    &mut moved,
                )
            };
            if s != K_CC_SUCCESS {
                ok = false;
                break;
            }
            pack_len = 0;
        }
    }

    let mut mac = [0u8; AES_BLOCK_SIZE];
    if ok {
        let s = unsafe {
            CCCryptorUpdate(
                cryptor,
                last.as_ptr() as *const c_void,
                AES_BLOCK_SIZE,
                mac.as_mut_ptr() as *mut c_void,
                AES_BLOCK_SIZE,
                &mut moved,
            )
        };
        ok = s == K_CC_SUCCESS && moved == AES_BLOCK_SIZE;
    }

    unsafe { CCCryptorRelease(cryptor) };
    ok.then_some(mac)
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
    fn sha256_incremental_matches_oneshot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let oneshot = sha256(data);
        let mut h = Sha256::new();
        h.update(&data[..10]);
        h.update(&data[10..]);
        assert_eq!(h.finalize(), oneshot);
    }

    #[test]
    fn sha256_empty_vector() {
        assert_eq!(
            hex_encode(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    fn decode_hex_vec(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        hex.as_bytes()
            .chunks_exact(2)
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
            .collect()
    }

    fn decode_hex_array<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        let mut out = [0u8; N];
        for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }

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
    fn test_md5_abc() {
        assert_eq!(hex_encode(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
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
    fn test_md4_abc() {
        assert_eq!(hex_encode(&md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
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
    fn test_hmac_md5_rfc2202_case_2() {
        let mac = hmac_md5(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(hex_encode(&mac), "750c783e6ab0b503eaa86e310a5db738");
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
    fn test_sha256_abc() {
        assert_eq!(
            hex_encode(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha512_abc() {
        assert_eq!(
            hex_encode(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
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

    #[test]
    fn test_hmac_sha256_rfc4231_case_1() {
        let key = [0x0b_u8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex_encode(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn test_aes128_ecb_block_nist_vector() {
        let key = decode_hex_array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let block = decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a");
        assert_eq!(
            aes128_ecb_block(&key, &block),
            decode_hex_array::<16>("3ad77bb40d7a3660a89ecaf32466ef97")
        );
    }

    #[test]
    fn test_aes128_cmac_rfc4493_vectors() {
        let key = decode_hex_array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let cases = [
            ("", "bb1d6929e95937287fa37d129b756746"),
            (
                "6bc1bee22e409f96e93d7e117393172a",
                "070a16b46b4d4144f79bdd9dd04a287c",
            ),
            (
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
                "dfa66747de9ae63030ca32611497c827",
            ),
            (
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "51f0bebf7e3b9d92fc49741779363cfe",
            ),
        ];

        for (message, expected) in cases {
            let message = decode_hex_vec(message);
            assert_eq!(
                aes128_cmac(&key, &message),
                decode_hex_array::<16>(expected)
            );
            // Multi-slice must match the contiguous path for every split.
            if message.len() >= 2 {
                let mid = message.len() / 2;
                assert_eq!(
                    aes128_cmac_parts(&key, &[&message[..mid], &message[mid..]]),
                    decode_hex_array::<16>(expected)
                );
            }
            if message.len() >= 3 {
                let a = message.len() / 3;
                let b = 2 * message.len() / 3;
                assert_eq!(
                    aes128_cmac_parts(&key, &[&message[..a], &message[a..b], &message[b..]]),
                    decode_hex_array::<16>(expected)
                );
            }
        }
    }

    #[test]
    fn test_dbl_block_rfc4493_subkeys() {
        let l = decode_hex_array::<16>("7df76b0c1ab899b33e42f047b91b546f");
        let k1 = dbl_block(&l);
        assert_eq!(
            k1,
            decode_hex_array::<16>("fbeed618357133667c85e08f7236a8de")
        );
        assert_eq!(
            dbl_block(&k1),
            decode_hex_array::<16>("f7ddac306ae266ccf90bc11ee46d513b")
        );
    }

    #[test]
    fn test_xor_block_in_place() {
        let mut block = decode_hex_array::<16>("00112233445566778899aabbccddeeff");
        xor_block(
            &mut block,
            &decode_hex_array::<16>("ffffffff00000000ffffffff00000000"),
        );
        assert_eq!(
            block,
            decode_hex_array::<16>("ffeeddcc4455667777665544ccddeeff")
        );
    }

    #[test]
    fn test_hex_encode_lowercase() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00, 0xab, 0xcd, 0xef]), "00abcdef");
    }
}
