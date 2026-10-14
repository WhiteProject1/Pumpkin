use std::{collections::HashMap, net::IpAddr, time::Duration};

use base64::{Engine, engine::general_purpose};
use pumpkin_config::{AuthenticationConfig, networking::auth::TextureConfig};
use pumpkin_protocol::Property;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use serde::Deserialize;
use thiserror::Error;
use ureq::http::{StatusCode, Uri};
use uuid::Uuid;

use super::GameProfile;

#[derive(Deserialize, Clone, Debug)]
#[expect(dead_code)]
#[serde(rename_all = "camelCase")]
pub struct ProfileTextures {
    timestamp: i64,
    profile_id: Uuid,
    profile_name: String,
    signature_required: bool,
    textures: HashMap<String, Texture>,
}

#[derive(Deserialize, Clone, Debug)]
#[expect(dead_code)]
pub struct Texture {
    url: String,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonPublicKey {
    pub public_key: String,
}
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MojangPublicKeys {
    pub profile_property_keys: Vec<JsonPublicKey>,
    pub player_certificate_keys: Vec<JsonPublicKey>,
    pub authentication_keys: Option<Vec<JsonPublicKey>>,
}

pub const MOJANG_BEDROCK_PUBLIC_KEY_BASE64: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECRXueJeTDqNRRgJi/vlRufByu/2G0i2Ebt6YMar5QX/R0DIIyrJMcUpruK4QveTfJSTp3Shlq4Gk34cD/4GUWwkv0DVuzeuB+tXija7HBxii03NHDbPAD0AKnLr2wdAp";
const MOJANG_AUTHENTICATION_URL: &str = "https://sessionserver.mojang.com/session/minecraft/hasJoined?username={username}&serverId={server_hash}";
const MOJANG_PREVENT_PROXY_AUTHENTICATION_URL: &str = "https://sessionserver.mojang.com/session/minecraft/hasJoined?username={username}&serverId={server_hash}";
const MOJANG_SERVICES_URL: &str = "https://api.minecraftservices.com/";

/// Sends a GET request to Mojang's authentication servers to verify a client's Minecraft account.
///
/// **Purpose:**
///
/// This function is used to ensure that a client connecting to the server has a valid, premium Minecraft account. It's a crucial step in preventing unauthorized access and maintaining server security.
///
/// **How it Works:**
///
/// 1. A client with a premium account sends a login request to the Mojang session server.
/// 2. Mojang's servers verify the client's credentials and add the player to the their Servers
/// 3. Now our server will send a Request to the Session servers and check if the Player has joined the Session Server .
///
/// See <https://pumpkinmc.org/developer/networking/authentication>
pub fn authenticate(
    username: &str,
    server_hash: &str,
    ip: &IpAddr,
    auth_config: &AuthenticationConfig,
) -> Result<GameProfile, AuthError> {
    // The username is client supplied: encode it so it can't smuggle extra query parameters
    // (`&`, `#`, ...) into the request.
    let username = percent_encode(username);
    let address = if auth_config.prevent_proxy_connections {
        let auth_url = auth_config
            .prevent_proxy_connection_auth_url
            .as_deref()
            .unwrap_or(MOJANG_PREVENT_PROXY_AUTHENTICATION_URL);

        auth_url
            .replace("{username}", &username)
            .replace("{server_hash}", server_hash)
            .replace("{ip}", &ip.to_string())
    } else {
        let auth_url = auth_config
            .url
            .as_deref()
            .unwrap_or(MOJANG_AUTHENTICATION_URL);

        auth_url
            .replace("{username}", &username)
            .replace("{server_hash}", server_hash)
    };

    // Bounded timeouts: without them a slow session server pins the calling thread forever.
    let connect_timeout = Duration::from_millis(u64::from(auth_config.connect_timeout.max(1)));
    let read_timeout = Duration::from_millis(u64::from(auth_config.read_timeout.max(1)));
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(connect_timeout))
        .timeout_global(Some(connect_timeout + read_timeout))
        .build()
        .into();
    let mut response = agent
        .get(address)
        .call()
        .map_err(|_| AuthError::FailedResponse)?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::NO_CONTENT => Err(AuthError::UnverifiedUsername)?,
        other => Err(AuthError::UnknownStatusCode(other))?,
    }
    let profile: GameProfile = response
        .body_mut()
        .read_json()
        .map_err(|_| AuthError::FailedParse)?;
    Ok(profile)
}

/// Percent-encodes everything outside the URL "unreserved" set.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

pub fn validate_textures(property: &Property, config: &TextureConfig) -> Result<(), TextureError> {
    let from64 = general_purpose::STANDARD
        .decode(&property.value)
        .map_err(|e| TextureError::DecodeError(e.to_string()))?;
    let textures: ProfileTextures =
        serde_json::from_slice(&from64).map_err(|e| TextureError::JSONError(e.to_string()))?;
    for texture in textures.textures {
        let url = texture
            .1
            .url
            .parse()
            .map_err(|_| TextureError::InvalidURL)?;
        is_texture_url_valid(&url, config)?;
    }
    Ok(())
}

pub fn is_texture_url_valid(url: &Uri, config: &TextureConfig) -> Result<(), TextureError> {
    let scheme = url.scheme().unwrap();
    if !config
        .allowed_url_schemes
        .iter()
        .any(|allowed_scheme| scheme.as_str().ends_with(allowed_scheme))
    {
        return Err(TextureError::DisallowedUrlScheme(scheme.to_string()));
    }
    let domain = url.authority().unwrap();
    if !config
        .allowed_url_domains
        .iter()
        .any(|allowed_domain| domain.as_str().ends_with(allowed_domain))
    {
        return Err(TextureError::DisallowedUrlDomain(domain.to_string()));
    }
    Ok(())
}

pub fn fetch_mojang_public_keys(
    auth_config: &AuthenticationConfig,
) -> Result<Vec<RsaPublicKey>, AuthError> {
    let services_url = auth_config
        .services_url
        .as_deref()
        .unwrap_or(MOJANG_SERVICES_URL);

    let url = format!("{services_url}/publickeys");

    let mut response = ureq::get(url)
        .call()
        .map_err(|_| AuthError::FailedResponse)?;

    match response.status() {
        StatusCode::OK => {}
        StatusCode::NO_CONTENT => Err(AuthError::FailedResponse)?,
        other => Err(AuthError::UnknownStatusCode(other))?,
    }

    let public_keys: MojangPublicKeys = response
        .body_mut()
        .read_json()
        .map_err(|_| AuthError::FailedParse)?;

    let as_rsa_keys = public_keys
        .player_certificate_keys
        .into_iter()
        .map(|key| {
            let decoded_key = general_purpose::STANDARD
                .decode(key.public_key.as_bytes())
                .map_err(|_| AuthError::FailedParse)?;
            RsaPublicKey::from_public_key_der(&decoded_key).map_err(|_| AuthError::FailedParse)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(as_rsa_keys)
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Authentication servers are down")]
    FailedResponse,
    #[error("Failed to verify username")]
    UnverifiedUsername,
    #[error("You are banned from Authentication servers")]
    Banned,
    #[error("Texture Error {0}")]
    TextureError(TextureError),
    #[error("You have disallowed actions from Authentication servers")]
    DisallowedAction,
    #[error("Failed to parse JSON into Game Profile")]
    FailedParse,
    #[error("Unknown Status Code {0}")]
    UnknownStatusCode(StatusCode),
}

#[derive(Error, Debug)]
pub enum TextureError {
    #[error("Invalid URL")]
    InvalidURL,
    #[error("Invalid URL scheme for player texture: {0}")]
    DisallowedUrlScheme(String),
    #[error("Invalid URL domain for player texture: {0}")]
    DisallowedUrlDomain(String),
    #[error("Failed to decode base64 player texture: {0}")]
    DecodeError(String),
    #[error("Failed to parse JSON from player texture: {0}")]
    JSONError(String),
}
