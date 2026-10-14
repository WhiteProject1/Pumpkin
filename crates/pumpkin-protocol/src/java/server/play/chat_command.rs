use pumpkin_data::packet::serverbound::play::CHAT_COMMAND;
use pumpkin_macros::java_packet;

use crate::{
    ServerPacket,
    ser::{NetworkReadSliceExt, ReadingError},
};
use pumpkin_util::version::JavaMinecraftVersion;

#[java_packet(CHAT_COMMAND)]
pub struct SChatCommand<'a> {
    pub command: &'a str,
}

impl<'a> ServerPacket<'a> for SChatCommand<'a> {
    fn read(bytebuf: &mut &'a [u8], _version: &JavaMinecraftVersion) -> Result<Self, ReadingError> {
        // Vanilla reads the command with `readUtf(256)`.
        Ok(Self {
            command: bytebuf.get_str_bounded_borrowed(256)?,
        })
    }
}

impl crate::ClientPacket for SChatCommand<'_> {
    fn write_packet_data(
        &self,
        mut write: impl std::io::Write,
        _version: &JavaMinecraftVersion,
    ) -> Result<(), crate::ser::WritingError> {
        use crate::ser::NetworkWriteExt;
        write.write_string(self.command)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ser::NetworkWriteExt;

    fn encoded(command: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_string(command).unwrap();
        buf
    }

    #[test]
    fn command_longer_than_vanilla_allows_is_rejected() {
        let version = JavaMinecraftVersion::V_26_3;

        let longest = encoded(&"a".repeat(256));
        let packet = SChatCommand::read(&mut longest.as_slice(), &version).unwrap();
        assert_eq!(packet.command.len(), 256);

        let too_long = encoded(&"a".repeat(257));
        assert!(SChatCommand::read(&mut too_long.as_slice(), &version).is_err());
    }
}
