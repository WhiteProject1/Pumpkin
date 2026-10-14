use std::io::Read;

use pumpkin_data::packet::serverbound::PLAY_CHAT_COMMAND;
use pumpkin_macros::java_packet;
use pumpkin_util::version::MinecraftVersion;

use crate::{
    ClientPacket, ServerPacket,
    ser::{NetworkReadExt, NetworkWriteExt, ReadingError, WritingError},
};

/// Vanilla reads the command with `readUtf(256)`; anything longer is a protocol error.
pub const MAX_COMMAND_LENGTH: usize = 256;

#[java_packet(PLAY_CHAT_COMMAND)]
pub struct SChatCommand {
    pub command: String,
}

impl ServerPacket for SChatCommand {
    fn read(mut read: impl Read, _version: &MinecraftVersion) -> Result<Self, ReadingError> {
        // The bound is in bytes while vanilla counts chars, so allow for multi-byte UTF-8 on the
        // wire and enforce the char limit afterwards.
        let command = read.get_string_bounded(MAX_COMMAND_LENGTH * 3)?;
        if command.chars().count() > MAX_COMMAND_LENGTH {
            return Err(ReadingError::TooLarge("command".to_string()));
        }
        Ok(Self { command })
    }
}

impl ClientPacket for SChatCommand {
    fn write_packet_data(
        &self,
        mut write: impl std::io::Write,
        _version: &MinecraftVersion,
    ) -> Result<(), WritingError> {
        write.write_string(&self.command)
    }
}
