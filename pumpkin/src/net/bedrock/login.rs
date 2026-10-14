use crate::net::authentication::MOJANG_BEDROCK_PUBLIC_KEY_BASE64;
use crate::{
    net::{ClientPlatform, DisconnectReason, GameProfile, bedrock::BedrockClient, can_not_join},
    server::Server,
};
use pumpkin_config::networking::compression::CompressionInfo;
use pumpkin_data::translation;
use pumpkin_protocol::bedrock::server::resource_pack_response::SResourcePackResponse;
use pumpkin_protocol::{
    bedrock::{
        client::{
            network_settings::CNetworkSettings, play_status::CPlayStatus,
            resource_pack_stack::CResourcePackStackPacket, resource_packs_info::CResourcePacksInfo,
            start_game::Experiments,
        },
        frame_set::FrameSet,
        server::{login::SLogin, request_network_settings::SRequestNetworkSettings},
    },
    codec::var_uint::VarUInt,
};
use pumpkin_util::jwt::{AuthError, verify_chain};
use pumpkin_util::text::TextComponent;
use pumpkin_world::CURRENT_BEDROCK_MC_VERSION;
use serde::Deserialize;
use std::sync::{Arc, atomic::Ordering};
use thiserror::Error;
use tracing::{debug, warn};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("Login packet data is not a valid JSON array of tokens")]
    InvalidTokenFormat(#[from] serde_json::Error),
    #[error("JWT chain validation failed: {0}")]
    ChainValidationFailed(#[from] AuthError),
    #[error("The validated username is invalid")]
    InvalidUsername,
    #[error("Could not parse UUID from validated token")]
    InvalidUuid,
    #[error("Received a second login packet")]
    AlreadyLoggedIn,
    #[error("The server is full")]
    ServerFull,
    #[error("The player is not allowed to join: {0}")]
    NotAllowed(String),
}

/// Mirrors the username rules of the Java login: at most 16 characters and no control characters or spaces.
fn is_valid_display_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 16 && !name.chars().any(|c| c.is_control() || c == ' ')
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FullLoginPayload {
    certificate: String,
}

#[derive(Deserialize, Debug)]
struct CertificateChainPayload {
    chain: Vec<String>,
}

impl BedrockClient {
    pub async fn handle_request_network_settings(&self, _packet: SRequestNetworkSettings) {
        self.send_game_packet(&CNetworkSettings::new(0, 0, false, 0, 0.0))
            .await;
        self.set_compression(CompressionInfo::default()).await;
    }

    pub async fn handle_login(self: &Arc<Self>, packet: SLogin, server: &Server) -> Option<()> {
        match self.try_handle_login(packet, server).await {
            Ok(()) => Some(()),
            Err(error) => {
                warn!("Bedrock login failed: {error}");
                let (reason, message) = match error {
                    LoginError::InvalidUsername => (
                        DisconnectReason::LoginPacketNoRequest,
                        "Your username is invalid.".to_string(),
                    ),
                    LoginError::AlreadyLoggedIn => (
                        DisconnectReason::Kicked,
                        "Received a second login packet.".to_string(),
                    ),
                    LoginError::ServerFull => (
                        DisconnectReason::ServerFull,
                        TextComponent::translate(
                            translation::MULTIPLAYER_DISCONNECT_SERVER_FULL,
                            [],
                        )
                        .get_text(),
                    ),
                    LoginError::NotAllowed(message) => (DisconnectReason::Kicked, message),
                    _ => (
                        DisconnectReason::LoginPacketNoRequest,
                        "Failed to log in. The data sent by your client was invalid.".to_string(),
                    ),
                };
                self.kick(reason, message).await;
                None
            }
        }
    }

    pub async fn try_handle_login(
        self: &Arc<Self>,
        packet: SLogin,
        server: &Server,
    ) -> Result<(), LoginError> {
        // A client logs in exactly once; the flag (rather than `self.player`) also covers two login
        // packets racing each other, since every datagram is handled in its own task.
        if self.login_started.swap(true, Ordering::AcqRel) {
            return Err(LoginError::AlreadyLoggedIn);
        }

        let outer_payload: FullLoginPayload = serde_json::from_slice(&packet.jwt)?;
        let inner_payload: CertificateChainPayload =
            serde_json::from_str(&outer_payload.certificate)?;

        let chain_vec: Vec<&str> = inner_payload.chain.iter().map(String::as_str).collect();
        let player_data = verify_chain(&chain_vec, MOJANG_BEDROCK_PUBLIC_KEY_BASE64)?;

        if !is_valid_display_name(&player_data.display_name) {
            return Err(LoginError::InvalidUsername);
        }

        let profile = GameProfile {
            id: Uuid::parse_str(&player_data.uuid).map_err(|_| LoginError::InvalidUuid)?,
            name: player_data.display_name,
            properties: Vec::new(),
            profile_actions: None,
        };

        // Don't allow new logons when the server is full.
        // If `max_players` is set to zero, then there is no max player count enforced.
        let max_players = server.basic_config.max_players;
        if max_players > 0 && server.get_player_count() >= max_players as usize {
            return Err(LoginError::ServerFull);
        }

        if let Some(reason) = can_not_join(&profile, &self.address, server).await {
            return Err(LoginError::NotAllowed(reason.get_text()));
        }

        //let raw_token = unsafe { String::from_utf8_unchecked(packet.raw_token) };
        //let raw_token: Vec<&str> = raw_token.split('.').collect();
        // We dont care about the validation, we just want to get the data
        //let _raw_token = unsafe {
        //    String::from_utf8_unchecked(general_purpose::URL_SAFE_NO_PAD.decode(raw_token[1]).unwrap())
        //};

        let mut frame_set = FrameSet::default();

        self.write_game_packet_to_set(&CPlayStatus::LoginSuccess, &mut frame_set)
            .await;
        self.write_game_packet_to_set(
            &CResourcePacksInfo::new(false, false, false, false, Uuid::default(), String::new()),
            &mut frame_set,
        )
        .await;

        self.send_frame_set(frame_set, 0x84).await;

        if let Some((player, world)) = server
            .add_player(ClientPlatform::Bedrock(self.clone()), profile, None)
            .await
        {
            world
                .spawn_bedrock_player(&server.basic_config, player.clone(), server)
                .await;
            *self.player.lock().await = Some(player);
        }

        Ok(())
    }

    pub async fn handle_resource_pack_response(&self, packet: SResourcePackResponse) {
        // TODO: Add all
        if packet.response == SResourcePackResponse::STATUS_HAVE_ALL_PACKS {
            debug!("Bedrock: STATUS_HAVE_ALL_PACKS");
            let mut frame_set = FrameSet::default();

            self.write_game_packet_to_set(
                &CResourcePackStackPacket::new(
                    false,
                    VarUInt(0),
                    CURRENT_BEDROCK_MC_VERSION.to_string(),
                    Experiments {
                        names_size: 0,
                        experiments_ever_toggled: false,
                    },
                    false,
                ),
                &mut frame_set,
            )
            .await;
            self.send_frame_set(frame_set, 0x84).await;
        }
    }
}
