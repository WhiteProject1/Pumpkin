/// Proxy implementation for Velocity <https://papermc.io/software/velocity> by `PaperMC`
/// Sadly, `PaperMC` does not care about 3rd parties providing support for Velocity. There is no documentation.
/// I had to understand the code logic by looking at `PaperMC`'s Velocity implementation: <https://github.com/PaperMC/Paper/blob/0cf731589a3b6923542cdfc36dbcee9c47c51076/paper-server/src/main/java/com/destroystokyo/paper/proxy/VelocityProxy.java>
use std::{
    io::Read,
    net::{IpAddr, SocketAddr},
};

use bytes::{BufMut, BytesMut};
use hmac::{Hmac, KeyInit, Mac};
use pumpkin_config::networking::proxy::VelocityConfig;
use pumpkin_protocol::{
    Property, java::client::login::CLoginPluginRequest, java::server::login::SLoginPluginResponse,
    ser::NetworkReadExt,
};
use rand::RngExt;
use sha2::Sha256;
use thiserror::Error;
use tracing::debug;

use crate::net::{GameProfile, java::JavaClient};

type HmacSha256 = Hmac<Sha256>;

const MAX_SUPPORTED_FORWARDING_VERSION: u8 = 4;
const PLAYER_INFO_CHANNEL: &str = "velocity:player_info";

#[derive(Error, Debug)]
pub enum VelocityError {
    #[error("No response data received")]
    NoData,
    #[error("Unable to verify player details")]
    FailedVerifyIntegrity,
    #[error("Failed to read forward version")]
    FailedReadForwardVersion,
    #[error("Unsupported forwarding version {0}. Maximum supported version is {1}")]
    UnsupportedForwardVersion(u8, u8),
    #[error("Failed to read address")]
    FailedReadAddress,
    #[error("Failed to parse address")]
    FailedParseAddress,
    #[error("Failed to read game profile name")]
    FailedReadProfileName,
    #[error("Failed to read game profile UUID")]
    FailedReadProfileUUID,
    #[error("Failed to read game profile properties")]
    FailedReadProfileProperties,
}

pub async fn velocity_login(client: &JavaClient) {
    let velocity_message_id: i32 = rand::rng().random();
    // The response must carry this id back; see `handle_plugin_response`.
    client.velocity_message_id.store(Some(velocity_message_id));

    let mut buf = BytesMut::new();
    buf.put_u8(MAX_SUPPORTED_FORWARDING_VERSION);
    client
        .enqueue_packet(&CLoginPluginRequest::new(
            velocity_message_id.into(),
            PLAYER_INFO_CHANNEL,
            &buf,
        ))
        .await;
}

#[must_use]
pub fn check_integrity(data: (&[u8], &[u8]), secret: &str) -> bool {
    let (signature, data_without_signature) = data;
    // Our fault, we can panic/expect?
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(data_without_signature);
    mac.verify_slice(signature).is_ok()
}

fn read_game_profile(read: impl Read) -> Result<GameProfile, VelocityError> {
    let mut read = read;
    let id = read
        .get_uuid()
        .map_err(|_| VelocityError::FailedReadProfileUUID)?;

    let name = read
        .get_string()
        .map_err(|_| VelocityError::FailedReadProfileName)?;

    let properties = read
        .get_list(|data| {
            let name = data.get_string()?;
            let value = data.get_string()?;
            let signature = data.get_option(NetworkReadExt::get_string)?;

            Ok(Property {
                name,
                value,
                signature,
            })
        })
        .map_err(|_| VelocityError::FailedReadProfileProperties)?;

    Ok(GameProfile {
        id,
        name,
        properties,
        profile_actions: None,
    })
}

pub fn receive_velocity_plugin_response(
    port: u16,
    config: &VelocityConfig,
    response: SLoginPluginResponse,
) -> Result<(GameProfile, SocketAddr), VelocityError> {
    debug!("Received velocity response");
    if let Some(data) = response.data {
        // The payload starts with a 32 byte HMAC; anything shorter is not a Velocity response.
        let Some((signature, mut data_without_signature)) = data.split_at_checked(32) else {
            return Err(VelocityError::NoData);
        };

        if !check_integrity((signature, data_without_signature), &config.secret) {
            return Err(VelocityError::FailedVerifyIntegrity);
        }

        // Check velocity version
        let version = data_without_signature
            .get_var_int()
            .map_err(|_| VelocityError::FailedReadForwardVersion)?;

        let version = u8::try_from(version.0).map_err(|_| {
            VelocityError::UnsupportedForwardVersion(u8::MAX, MAX_SUPPORTED_FORWARDING_VERSION)
        })?;
        if version > MAX_SUPPORTED_FORWARDING_VERSION {
            return Err(VelocityError::UnsupportedForwardVersion(
                version,
                MAX_SUPPORTED_FORWARDING_VERSION,
            ));
        }
        let addr = data_without_signature
            .get_string()
            .map_err(|_| VelocityError::FailedReadAddress)?;

        let socket_addr: SocketAddr = SocketAddr::new(
            addr.parse::<IpAddr>()
                .map_err(|_| VelocityError::FailedParseAddress)?,
            port,
        );

        let profile = read_game_profile(&mut data_without_signature)?;
        return Ok((profile, socket_addr));
    }
    Err(VelocityError::NoData)
}
