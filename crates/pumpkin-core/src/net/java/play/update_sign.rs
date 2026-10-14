#[allow(clippy::wildcard_imports)]
use super::*;

impl JavaClient {
    pub fn handle_sign_update(&self, player: &Player, sign_data: &SUpdateSign<'_>) {
        let world = player.get_entity().world.load_full();
        let Some(block_entity) = world.get_block_entity(&sign_data.location) else {
            return;
        };
        let Some(sign_entity) =
            crate::block::entities::sign::SignEntityRef::from_block_entity(&*block_entity)
        else {
            return;
        };
        if sign_entity.is_waxed() {
            return;
        }

        let currently_editing = *sign_entity
            .currently_editing_player()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(editor_id) = currently_editing
            && editor_id != player.gameprofile.id
        {
            return;
        }

        // Like vanilla's `StringUtil.filterText`.
        let filtered = [
            filter_sign_line(sign_data.line_1),
            filter_sign_line(sign_data.line_2),
            filter_sign_line(sign_data.line_3),
            filter_sign_line(sign_data.line_4),
        ];
        let lines = filtered.to_vec();

        if let Some(player_arc) = world.get_player_by_uuid(player.gameprofile.id) {
            let mut event = crate::plugin::api::events::block::sign_change::SignChangeEvent::new(
                player_arc,
                sign_data.location,
                lines,
            );
            if let Some(server) = world.server.upgrade() {
                server.plugin_manager.fire_blocking(&server, &mut event);
            }
            if event.cancelled {
                return;
            }
        }

        let text = sign_entity.get_text(sign_data.is_front_text);

        let new_messages = filtered.map(Box::<str>::from);

        text.messages
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone_from(&new_messages);
        // We do not filter anything, so the filtered copy has to track the raw one. Leaving it
        // empty makes it differ, which puts an empty `filtered_messages` on the wire and blanks
        // the sign for clients that render with text filtering enabled.
        *text
            .filtered_messages
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = new_messages;
        *sign_entity
            .currently_editing_player()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        world.update_block_entity(&block_entity);
    }
}

/// Drops `§` and control characters.
fn filter_sign_line(line: &str) -> String {
    line.chars()
        .filter(|c| *c != '§' && *c >= ' ' && *c != '\x7F')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::filter_sign_line;

    #[test]
    fn strips_formatting_and_control_characters() {
        assert_eq!(filter_sign_line("§cRed\u{1b}[31m\x7F text"), "cRed[31m text");
        assert_eq!(filter_sign_line("plain line"), "plain line");
        assert_eq!(filter_sign_line("ünïcödé ok"), "ünïcödé ok");
    }
}
