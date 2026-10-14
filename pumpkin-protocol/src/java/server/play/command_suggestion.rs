use std::io::Read;

use pumpkin_data::packet::serverbound::PLAY_COMMAND_SUGGESTION;
use pumpkin_macros::java_packet;
use pumpkin_util::version::MinecraftVersion;

use crate::{
    ServerPacket, VarInt,
    ser::{NetworkReadExt, ReadingError},
};

/// Vanilla reads the text with `readUtf(32500)`.
const MAX_TEXT_LENGTH: usize = 32500;

#[java_packet(PLAY_COMMAND_SUGGESTION)]
pub struct SCommandSuggestion {
    pub id: VarInt,
    pub command: String,
}

impl ServerPacket for SCommandSuggestion {
    fn read(mut read: impl Read, _version: &MinecraftVersion) -> Result<Self, ReadingError> {
        let id = read.get_var_int()?;
        let command = read.get_string_bounded(MAX_TEXT_LENGTH * 3)?;
        if command.chars().count() > MAX_TEXT_LENGTH {
            return Err(ReadingError::TooLarge("command suggestion".to_string()));
        }
        Ok(Self { id, command })
    }
}
