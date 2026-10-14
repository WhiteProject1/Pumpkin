//! # JWT Verifier for Minecraft: Bedrock Edition
//!
//! This module provides the core functionality for verifying the chain of JWT tokens
//! sent by a Minecraft: Bedrock Edition client. It handles cryptographic signature
//! verification, public key extraction, and decoding of player data.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose};
use ecdsa::Signature;
use p384::PublicKey;
use p384::ecdsa::{VerifyingKey, signature::Verifier};
use p384::pkcs8::DecodePublicKey;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

/// Number of tokens in a Mojang-issued certificate chain:
/// the client's self-signed token, the Mojang root token and the Mojang authentication token.
const CHAIN_LENGTH: usize = 3;
/// Index of the token in the chain that must be signed by the Mojang root key.
const MOJANG_SIGNED_INDEX: usize = 1;
/// Tolerated clock difference (in seconds) when checking the `exp` and `nbf` claims.
const CLOCK_DRIFT_MAX: i64 = 60;

/// Represents the claims extracted from the player's JWT token.
///
/// This struct contains the player's display name, UUID, and XUID.
#[derive(Debug, Deserialize)]
pub struct PlayerClaims {
    /// The player's display name (in-game name).
    #[serde(rename = "displayName")]
    pub display_name: String,
    /// The player's unique identifier (UUID).
    #[serde(rename = "identity")]
    pub uuid: String,
    /// The player's Xbox User ID (XUID).
    #[serde(rename = "XUID")]
    pub xuid: String,
}

/// Represents the possible errors that can occur during JWT verification.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Indicates that a JWT token has an invalid format (not enough parts).
    #[error("Invalid token format")]
    InvalidTokenFormat,
    /// Indicates that the chain does not have the expected number of tokens.
    #[error("Expected a chain of {CHAIN_LENGTH} tokens, got {0}")]
    InvalidChainLength(usize),
    /// Indicates that a token's `exp` claim lies in the past.
    #[error("Token has expired")]
    TokenExpired,
    /// Indicates that a token's `nbf` claim lies in the future.
    #[error("Token is not valid yet")]
    TokenNotYetValid,
    /// Indicates that the 'x5u' (X.509 URL) header parameter is missing from a token.
    #[error("x5u not found in header")]
    MissingX5U,
    /// Indicates a failure in Base64 decoding.
    #[error("Base64 decoding failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    /// Indicates a failure in parsing JSON data.
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),
    /// Indicates a failure in building a public key from its representation.
    #[error("Public key build failed: {0}")]
    PublicKeyBuild(String),
    /// Indicates that the token was not signed by the trusted Mojang public key.
    #[error("Token not signed by trusted Mojang key")]
    MojangKeyMismatch,
    /// Indicates that the token's signature is invalid.
    #[error("Invalid signature")]
    InvalidSignature,
    /// Indicates an error related to ECDSA signature operations.
    #[error("ECDSA signature error: {0}")]
    Ecdsa(#[from] ecdsa::Error),
}

/// Decodes a Base64 URL-safe encoded string with no padding.
///
/// # Arguments
///
/// * `s` - The Base64 URL-safe encoded string to decode.
///
/// # Returns
///
/// A `Result` containing the decoded bytes or a `base64::DecodeError`.
pub fn decode_b64_url_nopad(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::URL_SAFE_NO_PAD.decode(s)
}

/// Decodes a standard Base64 encoded string.
///
/// # Arguments
///
/// * `s` - The standard Base64 encoded string to decode.
///
/// # Returns
///
/// A `Result` containing the decoded bytes or a `base64::DecodeError`.
pub fn decode_b64_standard(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(s)
}

/// Builds a P-384 public key from a Base64 encoded string.
///
/// This function supports several common public key formats.
///
/// # Arguments
///
/// * `b64` - The Base64 encoded public key.
///
/// # Returns
///
/// A `Result` containing the `p384::PublicKey` or an `AuthError`.
pub fn build_public_key_from_b64(b64: &str) -> Result<PublicKey, AuthError> {
    let bytes = decode_b64_standard(b64)?;

    if !bytes.is_empty() && bytes[0] == 0x30 {
        PublicKey::from_public_key_der(&bytes).map_err(|e| AuthError::PublicKeyBuild(e.to_string()))
    } else if bytes.len() == 97 && bytes[0] == 0x04 {
        PublicKey::from_sec1_bytes(&bytes).map_err(|e| AuthError::PublicKeyBuild(e.to_string()))
    } else if bytes.len() == 96 {
        let mut sec1 = Vec::with_capacity(97);
        sec1.push(0x04u8);
        sec1.extend_from_slice(&bytes);
        PublicKey::from_sec1_bytes(&sec1).map_err(|e| AuthError::PublicKeyBuild(e.to_string()))
    } else {
        Err(AuthError::PublicKeyBuild(format!(
            "Unsupported key format/length: {} bytes",
            bytes.len()
        )))
    }
}

/// Decodes the header of a JWT and extracts the 'x5u' (X.509 URL) value.
///
/// # Arguments
///
/// * `header_b64` - The Base64 URL-safe encoded header of the JWT.
///
/// # Returns
///
/// A `Result` containing the 'x5u' value as a string or an `AuthError`.
pub fn decode_header_get_x5u(header_b64: &str) -> Result<String, AuthError> {
    let header_bytes = decode_b64_url_nopad(header_b64)?;
    let header_json: Value = serde_json::from_slice(&header_bytes)?;
    if let Some(x5u) = header_json.get("x5u")
        && let Some(s) = x5u.as_str()
    {
        return Ok(s.to_string());
    }
    Err(AuthError::MissingX5U)
}

/// Checks the `exp` and `nbf` claims of a token payload against the current time.
///
/// Both claims are optional. A claim that is present but not an integer is treated as failing,
/// so a malformed claim can never widen a token's validity window.
fn verify_time_claims(payload: &Value, now: i64) -> Result<(), AuthError> {
    if let Some(exp) = payload.get("exp")
        && exp.as_i64().unwrap_or(i64::MIN) < now - CLOCK_DRIFT_MAX
    {
        return Err(AuthError::TokenExpired);
    }
    if let Some(nbf) = payload.get("nbf")
        && nbf.as_i64().unwrap_or(i64::MAX) > now + CLOCK_DRIFT_MAX
    {
        return Err(AuthError::TokenNotYetValid);
    }
    Ok(())
}

/// Verifies a chain of JWT tokens from a Minecraft: Bedrock Edition client.
///
/// This function performs the following steps:
/// 1. Requires the chain to consist of exactly three tokens.
/// 2. Decodes and verifies each token in the chain, including its `exp` and `nbf` claims.
/// 3. Ensures that the chain is properly linked, with each token being signed by the key from the previous one.
/// 4. Verifies that the second token in the chain is signed by the trusted Mojang public key.
/// 5. Extracts and returns the player's claims from the final token in the chain.
///
/// # Arguments
///
/// * `raw_chain` - A slice of strings, where each string is a raw JWT token.
/// * `mojang_key_b64` - The Base64 encoded Mojang public key.
///
/// # Returns
///
/// A `Result` containing the `PlayerClaims` if verification is successful, or an `AuthError` if it fails.
pub fn verify_chain(raw_chain: &[&str], mojang_key_b64: &str) -> Result<PlayerClaims, AuthError> {
    let mojang_pk = VerifyingKey::from(build_public_key_from_b64(mojang_key_b64)?);

    let tokens: Vec<String> = raw_chain
        .iter()
        .map(|t| t.trim().replace(['\n', '\r'], ""))
        .collect();

    // A shorter chain (e.g. a single self-signed token) would never reach the token that has to
    // be signed by Mojang, letting the client pick its own identity.
    if tokens.len() != CHAIN_LENGTH {
        return Err(AuthError::InvalidChainLength(tokens.len()));
    }

    let first_token = tokens.first().ok_or(AuthError::InvalidTokenFormat)?;
    let first_header_b64 = first_token
        .split('.')
        .next()
        .ok_or(AuthError::InvalidTokenFormat)?;

    let mut current_verifying_key = VerifyingKey::from(build_public_key_from_b64(
        &decode_header_get_x5u(first_header_b64)?,
    )?);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default();

    let mut mojang_signed = false;

    // 4. Verification Loop
    for (i, token) in tokens.iter().enumerate() {
        let (signing_input, b64_sig) = token
            .rsplit_once('.')
            .ok_or(AuthError::InvalidTokenFormat)?;

        let sig_bytes = decode_b64_url_nopad(b64_sig)?;
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| AuthError::InvalidSignature)?;

        current_verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| AuthError::InvalidSignature)?;

        if i == MOJANG_SIGNED_INDEX {
            if current_verifying_key != mojang_pk {
                return Err(AuthError::MojangKeyMismatch);
            }
            mojang_signed = true;
        }

        let payload_b64 = signing_input
            .split('.')
            .nth(1)
            .ok_or(AuthError::InvalidTokenFormat)?;
        let payload_bytes = decode_b64_url_nopad(payload_b64)?;
        let payload: Value = serde_json::from_slice(&payload_bytes)?;

        verify_time_claims(&payload, now)?;

        if let Some(next_key_b64) = payload.get("identityPublicKey").and_then(|v| v.as_str()) {
            current_verifying_key = VerifyingKey::from(build_public_key_from_b64(next_key_b64)?);
        }
    }

    if !mojang_signed {
        return Err(AuthError::MojangKeyMismatch);
    }

    let last_token = tokens.last().ok_or(AuthError::InvalidTokenFormat)?;
    let last_payload_b64 = last_token
        .split('.')
        .nth(1)
        .ok_or(AuthError::InvalidTokenFormat)?;
    let payload_bytes = decode_b64_url_nopad(last_payload_b64)?;
    let v: Value = serde_json::from_slice(&payload_bytes)?;
    let extra_data: PlayerClaims = serde_json::from_value(v["extraData"].clone())?;

    Ok(extra_data)
}
