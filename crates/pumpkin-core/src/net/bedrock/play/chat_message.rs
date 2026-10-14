use crate::{error::PumpkinError, log_at_level, net::java::play::ChatError};

#[allow(clippy::wildcard_imports)]
use super::*;

/// Runs the vanilla message checks that apply to every edition; the Java
/// handler runs the same two before its signature checks.
fn validate_chat_message(message: &str) -> Result<(), ChatError> {
    // If we're able to find the 257th UTF-16 character, the message is too big.
    if message.encode_utf16().nth(256).is_some() {
        return Err(ChatError::OversizedMessage);
    }
    if message.chars().any(|c| c == '§' || c < ' ' || c == '\x7F') {
        return Err(ChatError::IllegalCharacters);
    }
    Ok(())
}

impl BedrockClient {
    pub async fn handle_chat_message(
        &self,
        server: &Arc<Server>,
        player: &Arc<Player>,
        packet: SText<'_>,
    ) {
        player.update_last_action_time();
        let gameprofile = &player.gameprofile;

        if let Err(err) = validate_chat_message(&packet.message) {
            log_at_level!(
                err.severity(),
                "{} (uuid {}) {}",
                gameprofile.name,
                gameprofile.id,
                err
            );
            if err.is_kick()
                && let Some(reason) = err.client_kick_reason()
            {
                self.kick(DisconnectReason::Kicked, reason).await;
            }
            return;
        }

        if player.check_chat_spam(server, crate::entity::player::SpamType::Chat) {
            return;
        }

        send_cancellable! {{
            server;
            PlayerChatEvent::new(player.clone(), packet.message.into_owned(), vec![], None);

            'after: {
                info!("<chat> {}: {}", gameprofile.name, event.message);

                let config = &server.advanced_config;

                let message = match seasonal_events::modify_chat_message(&event.message, config) {
                    Some(m) => m,
                    None => event.message.clone(),
                };

                let decorated_message = TextComponent::chat_decorated(
                    &config.chat.format,
                    &gameprofile.name,
                    &message,
                );

                let entity = &player.get_entity();
                if server.basic_config.allow_chat_reports {
                    //TODO Alex help, what is this?
                    //world.broadcast_secure_player_chat(player, &message, decorated_message).await;
                } else {
                    let je_packet = CSystemChatMessage::new(
                        &decorated_message,
                        false,
                    );

                    let be_packet = SText::chat_with_xuid(
                        message,
                        gameprofile.name.clone(),
                        packet.xuid.into_owned(),
                        packet.filtered_message.map(std::borrow::Cow::into_owned),
                    );

                    entity.world.load().broadcast_editioned(&je_packet, &be_packet);
                }
            }
        }}
    }
}

#[cfg(test)]
mod tests {
    use super::{ChatError, validate_chat_message};

    #[test]
    fn messages_over_256_utf16_units_are_rejected() {
        assert!(validate_chat_message(&"a".repeat(256)).is_ok());
        assert!(matches!(
            validate_chat_message(&"a".repeat(257)),
            Err(ChatError::OversizedMessage)
        ));
    }

    #[test]
    fn section_signs_and_control_characters_are_rejected() {
        assert!(validate_chat_message("hello").is_ok());
        for message in ["§chello", "hel\nlo", "hel\x7Flo"] {
            assert!(matches!(
                validate_chat_message(message),
                Err(ChatError::IllegalCharacters)
            ));
        }
    }
}
