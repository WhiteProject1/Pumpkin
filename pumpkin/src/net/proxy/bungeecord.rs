use std::{net::IpAddr, net::SocketAddr};

use thiserror::Error;
use tokio::sync::Mutex;

use crate::net::{GameProfile, offline_uuid};

#[derive(Error, Debug)]
pub enum BungeeCordError {
    #[error("Failed to parse address")]
    FailedParseAddress,
    #[error("Failed to parse UUID")]
    FailedParseUUID,
    #[error("Failed to parse properties")]
    FailedParseProperties,
    #[error("Failed to make offline UUID")]
    FailedMakeOfflineUUID,
    #[error(
        "If you wish to use IP forwarding, please enable it in your BungeeCord config as well!"
    )]
    MissingForwardingData,
}

/// Attempts to login a player via `BungeeCord`.
///
/// This function should be called when receiving the `SLoginStart` packet.
/// It utilizes the `server_address` received in the `SHandShake` packet,
/// which may contain optional data about the client:
///
/// 1. IP address (if `ip_forward` is enabled on the `BungeeCord` server)
/// 2. UUID (if `ip_forward` is enabled on the `BungeeCord` server)
/// 3. Game profile properties (if `ip_forward` and `online_mode` are enabled on the `BungeeCord` server)
///
/// The IP and UUID fields are mandatory, like Spigot requires them: a client that connects
/// directly (bypassing the proxy) must not be able to pick its own identity by omitting them.
/// Operators still need to firewall the backend port, as with any `BungeeCord` setup.
pub async fn bungeecord_login(
    _client_address: &Mutex<SocketAddr>,
    server_address: &str,
    name: String,
) -> Result<(IpAddr, GameProfile), BungeeCordError> {
    let mut parts = server_address.split('\0');

    // Skip the first part (the actual server address/host)
    let _host = parts.next();

    let ip = match parts.next() {
        Some(ip_str) if !ip_str.is_empty() => ip_str
            .parse()
            .map_err(|_| BungeeCordError::FailedParseAddress)?,
        _ => return Err(BungeeCordError::MissingForwardingData),
    };

    let id = match parts.next() {
        Some(uuid_str) if !uuid_str.is_empty() => uuid_str
            .parse()
            .map_err(|_| BungeeCordError::FailedParseUUID)?,
        _ => return Err(BungeeCordError::MissingForwardingData),
    };
    // Keep the offline derivation reachable for callers that need it.
    let _ = offline_uuid;

    let properties = match parts.next() {
        Some(json_str) if !json_str.is_empty() => {
            serde_json::from_str(json_str).map_err(|_| BungeeCordError::FailedParseProperties)?
        }
        _ => Vec::new(),
    };

    Ok((
        ip,
        GameProfile {
            id,
            name,
            properties,
            profile_actions: None,
        },
    ))
}
