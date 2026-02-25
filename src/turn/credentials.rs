// TURN credential generation and validation
//
// Implements the HMAC-SHA1 time-limited credential mechanism per
// draft-uberti-behave-turn-rest-00, which is the standard used by
// all major WebRTC implementations (Chrome, Firefox, Safari).
//
// Credential format:
//   Username: "{expiry_unix_timestamp}:{peer_id}"
//   Password: Base64(HMAC-SHA1(shared_secret, username))
//
// Also implements MESSAGE-INTEGRITY computation per RFC 5389 §15.4
// using long-term credentials (key = MD5(username:realm:password)).
//
// Nonce generation uses HMAC-SHA1 with an embedded timestamp for
// stateless stale-nonce detection.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::turn::error::TurnError;

// ---------------------------------------------------------------------------
// HMAC-SHA1 (RFC 2104)
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA1(key, message) returning a 20-byte digest.
///
/// This is a self-contained implementation of HMAC-SHA1 that doesn't
/// depend on external crates. In production, replace with `hmac` + `sha1`
/// crates for better performance and constant-time comparison.
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5C;

    // If key > block size, hash it first
    let key_block = if key.len() > BLOCK_SIZE {
        let hashed = sha1_digest(key);
        let mut block = [0u8; BLOCK_SIZE];
        block[..20].copy_from_slice(&hashed);
        block
    } else {
        let mut block = [0u8; BLOCK_SIZE];
        block[..key.len()].copy_from_slice(key);
        block
    };

    // Inner hash: SHA1(key XOR ipad || message)
    let mut inner_input = Vec::with_capacity(BLOCK_SIZE + message.len());
    for i in 0..BLOCK_SIZE {
        inner_input.push(key_block[i] ^ IPAD);
    }
    inner_input.extend_from_slice(message);
    let inner_hash = sha1_digest(&inner_input);

    // Outer hash: SHA1(key XOR opad || inner_hash)
    let mut outer_input = Vec::with_capacity(BLOCK_SIZE + 20);
    for i in 0..BLOCK_SIZE {
        outer_input.push(key_block[i] ^ OPAD);
    }
    outer_input.extend_from_slice(&inner_hash);
    sha1_digest(&outer_input)
}

// ---------------------------------------------------------------------------
// SHA-1 (FIPS 180-4)
// ---------------------------------------------------------------------------

/// Compute SHA-1 digest of the input data, returning a 20-byte hash.
///
/// This is a self-contained implementation. In production, use the `sha1` crate.
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    // Pre-processing: add padding
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) block
    for block in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999_u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1_u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC_u32),
                60..=79 => (b ^ c ^ d, 0xCA62C1D6_u32),
                _ => unreachable!(),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

// ---------------------------------------------------------------------------
// MD5 (RFC 1321) - needed for long-term credential key derivation
// ---------------------------------------------------------------------------

/// Compute MD5 digest of the input data, returning a 16-byte hash.
///
/// Used for the long-term credential key: `MD5(username:realm:password)`.
/// Self-contained implementation; in production use the `md-5` crate.
fn md5_digest(data: &[u8]) -> [u8; 16] {
    // Initial state
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Per-round shift amounts
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    // Pre-computed constants: floor(2^32 * |sin(i + 1)|)
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    // Pre-processing: add padding
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    // Process each 512-bit block
    for block in padded.chunks_exact(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                48..=63 => (c ^ (b | (!d)), (7 * i) % 16),
                _ => unreachable!(),
            };

            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]))
                    .rotate_left(S[i]),
            );
            a = temp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());
    result
}

// ---------------------------------------------------------------------------
// Base64 encoding (RFC 4648)
// ---------------------------------------------------------------------------

/// Encode bytes to base64 string using standard alphabet with padding.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    let chunks = data.chunks(3);

    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Decode a base64 string to bytes. Returns None on invalid input.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn char_val(c: u8) -> Option<u8> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        ALPHABET.iter().position(|&x| x == c).map(|p| p as u8)
    }

    let input = input.trim_end_matches('=');
    let bytes = input.as_bytes();

    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    let chunks = bytes.chunks(4);

    for chunk in chunks {
        let vals: Vec<u8> = chunk.iter().filter_map(|&b| char_val(b)).collect();
        if vals.len() != chunk.len() {
            return None;
        }

        let triple = match vals.len() {
            4 => {
                ((vals[0] as u32) << 18)
                    | ((vals[1] as u32) << 12)
                    | ((vals[2] as u32) << 6)
                    | (vals[3] as u32)
            }
            3 => {
                ((vals[0] as u32) << 18) | ((vals[1] as u32) << 12) | ((vals[2] as u32) << 6)
            }
            2 => ((vals[0] as u32) << 18) | ((vals[1] as u32) << 12),
            _ => return None,
        };

        result.push((triple >> 16) as u8);
        if vals.len() > 2 {
            result.push((triple >> 8 & 0xFF) as u8);
        }
        if vals.len() > 3 {
            result.push((triple & 0xFF) as u8);
        }
    }

    Some(result)
}

// ---------------------------------------------------------------------------
// Hex encoding (for nonces)
// ---------------------------------------------------------------------------

/// Encode bytes as lowercase hexadecimal string.
fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Decode a hexadecimal string to bytes. Returns None on invalid input.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut result = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        result.push(byte);
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// Credential generation / validation
// ---------------------------------------------------------------------------

/// Generate time-limited TURN credentials per draft-uberti-behave-turn-rest.
///
/// Returns `(username, password)` where:
/// - username = `"{expiry_timestamp}:{peer_id}"`
/// - password = `Base64(HMAC-SHA1(shared_secret, username))`
///
/// The credentials expire `ttl_secs` seconds from now.
pub fn generate_credentials(
    peer_id: &str,
    shared_secret: &[u8],
    ttl_secs: u64,
) -> (String, String) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expiry = now + ttl_secs;

    let username = format!("{}:{}", expiry, peer_id);
    let hmac = hmac_sha1(shared_secret, username.as_bytes());
    let password = base64_encode(&hmac);

    (username, password)
}

/// Validate time-limited TURN credentials.
///
/// 1. Parse the expiry timestamp from the username
/// 2. Check that the credentials have not expired
/// 3. Recompute HMAC-SHA1 and compare with the provided password
pub fn validate_credentials(
    username: &str,
    password: &str,
    shared_secret: &[u8],
) -> Result<(), TurnError> {
    // Parse expiry timestamp from username (format: "{timestamp}:{peer_id}")
    let colon_pos = username
        .find(':')
        .ok_or(TurnError::Unauthorized)?;

    let expiry_str = &username[..colon_pos];
    let expiry: u64 = expiry_str
        .parse()
        .map_err(|_| TurnError::Unauthorized)?;

    // Check expiry
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now > expiry {
        return Err(TurnError::Unauthorized);
    }

    // Recompute HMAC-SHA1 and compare
    let expected_hmac = hmac_sha1(shared_secret, username.as_bytes());
    let expected_password = base64_encode(&expected_hmac);

    if !constant_time_eq(password.as_bytes(), expected_password.as_bytes()) {
        return Err(TurnError::Unauthorized);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// MESSAGE-INTEGRITY computation (RFC 5389 §15.4)
// ---------------------------------------------------------------------------

/// Compute the long-term credential key per RFC 5389 §15.4:
/// `key = MD5(username ":" realm ":" password)`
pub fn compute_long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let input = format!("{}:{}:{}", username, realm, password);
    md5_digest(input.as_bytes())
}

/// Compute the MESSAGE-INTEGRITY attribute value (HMAC-SHA1).
///
/// `key` is the long-term credential key (output of [`compute_long_term_key`]).
/// `message_bytes` should be the STUN message up to (but not including) the
/// MESSAGE-INTEGRITY attribute, with the message length field adjusted to
/// include the MESSAGE-INTEGRITY attribute.
pub fn compute_message_integrity(key: &[u8], message_bytes: &[u8]) -> [u8; 20] {
    hmac_sha1(key, message_bytes)
}

/// Validate the MESSAGE-INTEGRITY attribute of a STUN message.
///
/// Recomputes the HMAC-SHA1 over the message bytes and compares it
/// with the provided MESSAGE-INTEGRITY value in constant time.
pub fn validate_message_integrity(
    message_integrity: &[u8; 20],
    key: &[u8],
    message_bytes: &[u8],
) -> bool {
    let expected = compute_message_integrity(key, message_bytes);
    constant_time_eq(&expected, message_integrity)
}

// ---------------------------------------------------------------------------
// Nonce generation / validation
// ---------------------------------------------------------------------------

/// Generate a NONCE that embeds a timestamp for stateless staleness detection.
///
/// Format: `{hex_timestamp}-{hex_hmac_of_timestamp}`
///
/// The server can validate the nonce without storing state by recomputing
/// the HMAC. The timestamp allows detecting stale nonces.
pub fn compute_nonce(timestamp: u64, secret: &[u8]) -> String {
    let ts_bytes = timestamp.to_be_bytes();
    let hmac = hmac_sha1(secret, &ts_bytes);
    // Use first 8 bytes of HMAC for a shorter nonce
    let hmac_short = &hmac[..8];
    format!("{}-{}", hex_encode(&ts_bytes), hex_encode(hmac_short))
}

/// Validate a NONCE and check that it hasn't expired.
///
/// 1. Parse the timestamp from the nonce
/// 2. Recompute HMAC and verify it matches
/// 3. Check that the nonce age doesn't exceed `max_age_secs`
pub fn validate_nonce(
    nonce: &str,
    secret: &[u8],
    max_age_secs: u64,
) -> Result<(), TurnError> {
    let parts: Vec<&str> = nonce.splitn(2, '-').collect();
    if parts.len() != 2 {
        return Err(TurnError::StaleNonce);
    }

    let ts_hex = parts[0];
    let hmac_hex = parts[1];

    // Decode timestamp
    let ts_bytes = hex_decode(ts_hex).ok_or(TurnError::StaleNonce)?;
    if ts_bytes.len() != 8 {
        return Err(TurnError::StaleNonce);
    }

    let timestamp = u64::from_be_bytes([
        ts_bytes[0], ts_bytes[1], ts_bytes[2], ts_bytes[3],
        ts_bytes[4], ts_bytes[5], ts_bytes[6], ts_bytes[7],
    ]);

    // Verify HMAC
    let expected_hmac = hmac_sha1(secret, &ts_bytes);
    let expected_hmac_hex = hex_encode(&expected_hmac[..8]);

    if !constant_time_eq(hmac_hex.as_bytes(), expected_hmac_hex.as_bytes()) {
        return Err(TurnError::StaleNonce);
    }

    // Check age
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now > timestamp + max_age_secs {
        return Err(TurnError::StaleNonce);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Compare two byte slices in constant time to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_empty() {
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let hash = sha1_digest(b"");
        let hex = hex_encode(&hash);
        assert_eq!(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn test_sha1_abc() {
        // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let hash = sha1_digest(b"abc");
        let hex = hex_encode(&hash);
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn test_md5_empty() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let hash = md5_digest(b"");
        let hex = hex_encode(&hash);
        assert_eq!(hex, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_abc() {
        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        let hash = md5_digest(b"abc");
        let hex = hex_encode(&hash);
        assert_eq!(hex, "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_hmac_sha1_rfc2202_test1() {
        // RFC 2202 Test Case 1:
        // Key  = 0x0b repeated 20 times
        // Data = "Hi There"
        // HMAC = b617318655057264e28bc0b6fb378c8ef146be00
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let hmac = hmac_sha1(&key, data);
        let hex = hex_encode(&hmac);
        assert_eq!(hex, "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    #[test]
    fn test_hmac_sha1_rfc2202_test2() {
        // RFC 2202 Test Case 2:
        // Key  = "Jefe"
        // Data = "what do ya want for nothing?"
        // HMAC = effcdf6ae5eb2fa2d27416d5f184df9c259a7c79
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let hmac = hmac_sha1(key, data);
        let hex = hex_encode(&hmac);
        assert_eq!(hex, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, TURN server!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_generate_validate_credentials() {
        let secret = b"supersecretkey";
        let peer_id = "12D3KooWTestPeerId";
        let ttl = 3600; // 1 hour

        let (username, password) = generate_credentials(peer_id, secret, ttl);

        // Username should contain the peer_id
        assert!(username.contains(peer_id));
        assert!(username.contains(':'));

        // Password should be valid base64
        assert!(base64_decode(&password).is_some());

        // Validation should succeed
        let result = validate_credentials(&username, &password, secret);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_credentials_wrong_password() {
        let secret = b"supersecretkey";
        let (username, _) = generate_credentials("test", secret, 3600);

        let result = validate_credentials(&username, "wrongpassword", secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_credentials_wrong_secret() {
        let secret = b"supersecretkey";
        let (username, password) = generate_credentials("test", secret, 3600);

        let result = validate_credentials(&username, &password, b"wrongsecret");
        assert!(result.is_err());
    }

    #[test]
    fn test_long_term_key() {
        // RFC 5389 example-ish: key = MD5("user:realm:pass")
        let key = compute_long_term_key("user", "realm", "pass");
        assert_eq!(key.len(), 16);

        // Should be deterministic
        let key2 = compute_long_term_key("user", "realm", "pass");
        assert_eq!(key, key2);
    }

    #[test]
    fn test_message_integrity_roundtrip() {
        let key = compute_long_term_key("alice", "duskchat.app", "password123");
        let message = b"fake stun message bytes for testing";

        let integrity = compute_message_integrity(&key, message);
        assert!(validate_message_integrity(&integrity, &key, message));

        // Tampered message should fail
        let tampered = b"tampered stun message bytes for testing";
        assert!(!validate_message_integrity(&integrity, &key, tampered));
    }

    #[test]
    fn test_nonce_roundtrip() {
        let secret = b"nonce_secret_key";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let nonce = compute_nonce(now, secret);
        assert!(nonce.contains('-'));

        // Should validate successfully with generous max age
        let result = validate_nonce(&nonce, secret, 3600);
        assert!(result.is_ok());
    }

    #[test]
    fn test_nonce_stale() {
        let secret = b"nonce_secret_key";
        // Use a timestamp from long ago
        let old_timestamp = 1000000;

        let nonce = compute_nonce(old_timestamp, secret);
        let result = validate_nonce(&nonce, secret, 3600);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_tampered() {
        let secret = b"nonce_secret_key";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let nonce = compute_nonce(now, secret);

        // Validate with wrong secret
        let result = validate_nonce(&nonce, b"wrong_secret", 3600);
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = &[0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = hex_encode(data);
        assert_eq!(encoded, "deadbeef");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(constant_time_eq(b"", b""));
    }
}
