use pumpkin_data::translation;
use pumpkin_protocol::{
    ConnectionState, KnownPack, Label, Link, LinkType,
    java::client::{
        config::{CConfigAddResourcePack, CConfigServerLinks, CKnownPacks},
        login::{CLoginSuccess, CSetCompression},
    },
    java::server::login::{
        SEncryptionResponse, SLoginCookieResponse, SLoginPluginResponse, SLoginStart,
    },
};
use pumpkin_util::text::TextComponent;
use std::net::SocketAddr;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::{
    net::{
        GameProfile,
        authentication::{self, AuthError},
        is_valid_player_name,
        java::{JavaClient, LoginStage},
        offline_uuid,
        proxy::{bungeecord, velocity},
    },
    server::Server,
};

impl JavaClient {
    pub async fn handle_login_start(&self, server: &Server, login_start: SLoginStart) {
        debug!("login start");
        if !self.expect_login_stage(LoginStage::Hello).await {
            return;
        }

        // Don't allow new logons when the server is full.
        // If `max_players` is set to zero, then there is no max player count enforced.
        // TODO: If client is an operator or has otherwise suitable elevated permissions, allow the client to bypass this requirement.
        let max_players = server.basic_config.max_players;
        if max_players > 0 && server.get_player_count() >= max_players as usize {
            self.kick(TextComponent::translate(
                translation::MULTIPLAYER_DISCONNECT_SERVER_FULL,
                [],
            ))
            .await;
            return;
        }

        if !is_valid_player_name(&login_start.name) {
            self.kick(TextComponent::text("Invalid characters in username"))
                .await;
            return;
        }

        let proxy = &server.advanced_config.networking.proxy;
        if proxy.enabled {
            if proxy.velocity.enabled {
                self.login_stage.store(LoginStage::AwaitingProxyResponse);
                velocity::velocity_login(self).await;
            } else if proxy.bungeecord.enabled {
                match bungeecord::bungeecord_login(
                    &self.address,
                    &self.server_address.lock().await,
                    login_start.name,
                )
                .await
                {
                    Ok((ip, profile)) => {
                        // Use the address the proxy forwarded so IP bans and logs see the
                        // player, not the proxy.
                        {
                            let mut address = self.address.lock().await;
                            *address = SocketAddr::new(ip, address.port());
                        }
                        self.complete_login(server, profile).await;
                    }
                    Err(error) => self.kick(TextComponent::text(error.to_string())).await,
                }
            } else {
                self.kick(TextComponent::text(
                    "Proxy support is enabled but no proxy type is configured",
                ))
                .await;
            }
            return;
        }

        let id = if server.basic_config.online_mode {
            // Only a placeholder: the authenticated profile replaces it after the
            // encryption response.
            login_start.uuid
        } else {
            offline_uuid(&login_start.name).expect("This is very not safe and bad")
        };

        let profile = GameProfile {
            id,
            name: login_start.name,
            properties: vec![],
            profile_actions: None,
        };

        if server.advanced_config.networking.packet_compression.enabled {
            self.enable_compression(server).await;
        }

        if server.basic_config.encryption {
            let verify_token: [u8; 4] = rand::random();
            *self.verify_token.lock().await = Some(verify_token);
            // Remember what the client claimed; it is not trusted until the key exchange
            // (and, in online mode, Mojang) confirmed it.
            *self.gameprofile.lock().await = Some(profile);
            self.login_stage.store(LoginStage::AwaitingKey);
            // Wait until we have sent the encryption packet to the client
            self.send_packet_now(
                &server
                    .encryption_request(&verify_token, server.basic_config.online_mode)
                    .await,
            )
            .await;
        } else {
            self.complete_login(server, profile).await;
        }
    }

    pub async fn handle_encryption_response(
        &self,
        server: &Server,
        encryption_response: SEncryptionResponse,
    ) {
        debug!("Handling encryption");
        if !self.expect_login_stage(LoginStage::AwaitingKey).await {
            return;
        }

        let shared_secret = match server.decrypt(&encryption_response.shared_secret).await {
            Ok(shared_secret) => shared_secret,
            Err(error) => {
                self.kick(TextComponent::text(error.to_string())).await;
                return;
            }
        };

        // The client must echo the token from our encryption request, encrypted with our
        // public key. This binds the response to this connection.
        let expected_token = self.verify_token.lock().await.take();
        let token_matches = match (
            expected_token,
            server.decrypt(&encryption_response.verify_token).await,
        ) {
            (Some(expected), Ok(received)) => received.as_slice() == expected,
            _ => false,
        };
        if !token_matches {
            self.kick(TextComponent::text("Invalid verify token")).await;
            return;
        }

        if let Err(error) = self.set_encryption(&shared_secret).await {
            self.kick(TextComponent::text(error.to_string())).await;
            return;
        }

        let claimed_profile = self.gameprofile.lock().await.clone();
        let Some(mut profile) = claimed_profile else {
            self.kick(TextComponent::text("No `GameProfile`")).await;
            return;
        };

        if server.basic_config.online_mode {
            // Online mode auth
            match self
                .authenticate(server, &shared_secret, &profile.name)
                .await
            {
                Ok(new_profile) => profile = new_profile,
                Err(error) => {
                    self.kick(match error {
                        AuthError::FailedResponse => TextComponent::translate(
                            translation::MULTIPLAYER_DISCONNECT_AUTHSERVERS_DOWN,
                            [],
                        ),
                        AuthError::UnverifiedUsername => TextComponent::translate(
                            translation::MULTIPLAYER_DISCONNECT_UNVERIFIED_USERNAME,
                            [],
                        ),
                        e => TextComponent::text(e.to_string()),
                    })
                    .await;
                    return;
                }
            }
        }

        self.complete_login(server, profile).await;
    }

    /// Finishes the login with an authenticated profile: rejects duplicate sessions, sends
    /// `LoginSuccess` and marks the connection as authenticated.
    async fn complete_login(&self, server: &Server, profile: GameProfile) {
        // Don't allow duplicate UUIDs
        if let Some(online_player) = &server.get_player_by_uuid(profile.id) {
            debug!(
                "Player (IP '{}', username '{}') tried to log in with the same UUID ('{}') as an online player (username '{}')",
                &self.address.lock().await,
                &profile.name,
                &profile.id,
                &online_player.gameprofile.name
            );
            self.kick(TextComponent::translate(
                translation::MULTIPLAYER_DISCONNECT_DUPLICATE_LOGIN,
                [],
            ))
            .await;
            return;
        }

        // Don't allow a duplicate username
        if let Some(online_player) = &server.get_player_by_name(&profile.name) {
            debug!(
                "A player (IP '{}', attempted username '{}') tried to log in with the same username as an online player (UUID '{}', username '{}')",
                &self.address.lock().await,
                &profile.name,
                &profile.id,
                &online_player.gameprofile.name
            );
            self.kick(TextComponent::translate(
                translation::MULTIPLAYER_DISCONNECT_DUPLICATE_LOGIN,
                [],
            ))
            .await;
            return;
        }

        let packet = CLoginSuccess::new(&profile.id, &profile.name, &profile.properties, false);
        self.send_packet_now(&packet).await;
        *self.gameprofile.lock().await = Some(profile);
        self.login_stage.store(LoginStage::Authenticated);
    }

    async fn enable_compression(&self, server: &Server) {
        let compression = server
            .advanced_config
            .networking
            .packet_compression
            .info
            .clone();
        // We want to wait until we have sent the compression packet to the client
        self.send_packet_now(&CSetCompression::new(
            compression.threshold.try_into().unwrap(),
        ))
        .await;
        self.set_compression(compression).await;
    }

    async fn authenticate(
        &self,
        server: &Server,
        shared_secret: &[u8],
        username: &str,
    ) -> Result<GameProfile, AuthError> {
        let hash = server.digest_secret(shared_secret).await;
        let ip = self.address.lock().await.ip();
        let auth_config = server.advanced_config.networking.authentication.clone();
        let username = username.to_string();
        // The session server request is blocking I/O; keep it off the async workers so a
        // slow or rate-limited Mojang can't stall the whole server.
        let profile = tokio::task::spawn_blocking(move || {
            authentication::authenticate(&username, &hash, &ip, &auth_config)
        })
        .await
        .map_err(|_| AuthError::FailedResponse)??;

        // Check if the player should join
        if let Some(actions) = &profile.profile_actions {
            if server
                .advanced_config
                .networking
                .authentication
                .player_profile
                .allow_banned_players
            {
                for allowed in &server
                    .advanced_config
                    .networking
                    .authentication
                    .player_profile
                    .allowed_actions
                {
                    if !actions.contains(allowed) {
                        return Err(AuthError::DisallowedAction);
                    }
                }
                if !actions.is_empty() {
                    return Err(AuthError::Banned);
                }
            } else if !actions.is_empty() {
                return Err(AuthError::Banned);
            }
        }
        // Validate textures
        for property in &profile.properties {
            authentication::validate_textures(
                property,
                &server.advanced_config.networking.authentication.textures,
            )
            .map_err(AuthError::TextureError)?;
        }
        Ok(profile)
    }

    pub fn handle_login_cookie_response(&self, packet: &SLoginCookieResponse) {
        // TODO: allow plugins to access this
        debug!(
            "Received cookie_response[login]: key: \"{}\", payload_length: \"{:?}\"",
            packet.key,
            packet.payload.as_ref().map(|p| p.len())
        );
    }
    pub async fn handle_plugin_response(
        &self,
        server: &Server,
        plugin_response: SLoginPluginResponse,
    ) {
        debug!("Handling plugin");
        if !self
            .expect_login_stage(LoginStage::AwaitingProxyResponse)
            .await
        {
            return;
        }
        let velocity_config = &server.advanced_config.networking.proxy.velocity;
        if !velocity_config.enabled {
            self.kick(TextComponent::text("Unexpected login plugin response"))
                .await;
            return;
        }
        if self.velocity_message_id.load() != Some(plugin_response.message_id.0) {
            warn!(
                "Client {} answered a login plugin request we did not send",
                self.id
            );
            self.kick(TextComponent::text("Unexpected login plugin response"))
                .await;
            return;
        }

        let port = self.address.lock().await.port();
        match velocity::receive_velocity_plugin_response(port, velocity_config, plugin_response) {
            Ok((profile, new_address)) => {
                *self.address.lock().await = new_address;
                self.complete_login(server, profile).await;
            }
            Err(error) => self.kick(TextComponent::text(error.to_string())).await,
        }
    }

    pub async fn handle_login_acknowledged(&self, server: &Server) {
        debug!("Handling login acknowledgement");
        // Only an authenticated client may enter the configuration phase: this is what
        // stops a client from skipping the encryption response altogether.
        if !self.expect_login_stage(LoginStage::Authenticated).await {
            return;
        }
        self.login_stage.store(LoginStage::Configuring);
        self.connection_state.store(ConnectionState::Config);
        self.send_packet_now(&server.get_branding()).await;

        if server.advanced_config.server_links.enabled {
            let mut links: Vec<Link> = Vec::new();

            let bug_report = &server.advanced_config.server_links.bug_report;
            if !bug_report.is_empty() {
                links.push(Link::new(Label::BuiltIn(LinkType::BugReport), bug_report));
            }

            let support = &server.advanced_config.server_links.support;
            if !support.is_empty() {
                links.push(Link::new(Label::BuiltIn(LinkType::Support), support));
            }

            let status = &server.advanced_config.server_links.status;
            if !status.is_empty() {
                links.push(Link::new(Label::BuiltIn(LinkType::Status), status));
            }

            let feedback = &server.advanced_config.server_links.feedback;
            if !feedback.is_empty() {
                links.push(Link::new(Label::BuiltIn(LinkType::Feedback), feedback));
            }

            let community = &server.advanced_config.server_links.community;
            if !community.is_empty() {
                links.push(Link::new(Label::BuiltIn(LinkType::Community), community));
            }

            let website = &server.advanced_config.server_links.website;
            if !website.is_empty() {
                links.push(Link::new(Label::BuiltIn(LinkType::Website), website));
            }

            let forums = &server.advanced_config.server_links.forums;
            if !forums.is_empty() {
                links.push(Link::new(Label::BuiltIn(LinkType::Forums), forums));
            }

            let news = &server.advanced_config.server_links.news;
            if !news.is_empty() {
                links.push(Link::new(Label::BuiltIn(LinkType::News), news));
            }

            let announcements = &server.advanced_config.server_links.announcements;
            if !announcements.is_empty() {
                links.push(Link::new(
                    Label::BuiltIn(LinkType::Announcements),
                    announcements,
                ));
            }

            for (key, value) in &server.advanced_config.server_links.custom {
                links.push(Link::new(
                    Label::TextComponent(TextComponent::text(key.clone()).into()),
                    value,
                ));
            }

            self.send_packet_now(&CConfigServerLinks::new(&links)).await;
        }

        let resource_config = &server.advanced_config.resource_pack;
        if resource_config.enabled {
            let uuid = Uuid::new_v3(&uuid::Uuid::NAMESPACE_DNS, resource_config.url.as_bytes());
            let resource_pack = CConfigAddResourcePack::new(
                &uuid,
                &resource_config.url,
                &resource_config.sha1,
                resource_config.force,
                if resource_config.prompt_message.is_empty() {
                    None
                } else {
                    Some(TextComponent::text(resource_config.prompt_message.clone()))
                },
            );

            self.send_packet_now(&resource_pack).await;
        } else {
            // This will be invoked by our resource pack handler in the case of the above branch.
            self.send_known_packs().await;
        }
        debug!("login acknowledged");
    }

    /// Send the known data packs to the client.
    pub async fn send_known_packs(&self) {
        self.send_packet_now(&CKnownPacks::new(&[KnownPack {
            namespace: "minecraft",
            id: "core",
            version: "1.21.11",
        }]))
        .await;
    }
}
