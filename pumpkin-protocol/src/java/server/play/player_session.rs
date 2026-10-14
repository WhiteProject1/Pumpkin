use std::io::Read;

use pumpkin_data::packet::serverbound::PLAY_CHAT_SESSION_UPDATE;
use pumpkin_macros::java_packet;
use pumpkin_util::version::MinecraftVersion;

use crate::{
    ServerPacket,
    ser::{NetworkReadExt, ReadingError},
};

#[derive(Debug)]
#[java_packet(PLAY_CHAT_SESSION_UPDATE)]
pub struct SPlayerSession {
    pub session_id: uuid::Uuid,
    pub expires_at: i64,
    pub public_key: Box<[u8]>,
    pub key_signature: Box<[u8]>,
}

impl ServerPacket for SPlayerSession {
    fn read(mut read: impl Read, _version: &MinecraftVersion) -> Result<Self, ReadingError> {
        let session_id = read.get_uuid()?;
        let expires_at = read.get_i64_be()?;

        // Vanilla limits: `ProfilePublicKey.MAX_KEY_LENGTH` / `MAX_SIGNATURE_LENGTH`
        const MAX_KEY_LENGTH: usize = 512;
        const MAX_SIGNATURE_LENGTH: usize = 4096;

        let public_key_length = read.get_var_int()?.0 as usize;
        if public_key_length > MAX_KEY_LENGTH {
            return Err(ReadingError::TooLarge("public key".to_string()));
        }
        let public_key = read.read_boxed_slice(public_key_length)?;

        let key_signature_length = read.get_var_int()?.0 as usize;
        if key_signature_length > MAX_SIGNATURE_LENGTH {
            return Err(ReadingError::TooLarge("key signature".to_string()));
        }
        let key_signature = read.read_boxed_slice(key_signature_length)?;

        Ok(Self {
            session_id,
            expires_at,
            public_key,
            key_signature,
        })
    }
}
