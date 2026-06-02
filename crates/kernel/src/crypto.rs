//! Password hashing and token generation/hashing.
//!
//! Passwords use Argon2id. Session/API tokens are random 256-bit secrets returned
//! to the caller exactly once; only their SHA-256 hash is stored, so a database
//! leak does not expose usable credentials.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use latentdb_contracts::ApiError;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Hash a plaintext password for storage.
pub fn hash_password(password: &str) -> latentdb_contracts::Result<String> {
    let mut salt_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| ApiError::internal(format!("salt error: {e}")))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ApiError::internal(format!("hash error: {e}")))?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored hash. Returns `Ok(false)` for a
/// mismatch and only errors if the stored hash is unparseable.
pub fn verify_password(password: &str, stored_hash: &str) -> latentdb_contracts::Result<bool> {
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|e| ApiError::internal(format!("stored hash invalid: {e}")))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Generate a fresh opaque token. Returns `(plaintext, sha256_hash)`. The
/// plaintext is shown to the caller once; only the hash is persisted.
pub fn new_token(prefix: &str) -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let secret = hex_encode(&bytes);
    let plaintext = format!("{prefix}{secret}");
    let hash = sha256_hex(&plaintext);
    (plaintext, hash)
}

/// SHA-256 hash of a token, hex-encoded — used to look up presented tokens.
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
