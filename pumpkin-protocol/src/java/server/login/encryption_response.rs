use std::io::Read;

use pumpkin_data::packet::serverbound::LOGIN_KEY;
use pumpkin_macros::java_packet;
use pumpkin_util::version::MinecraftVersion;

use crate::{ReadingError, ServerPacket, ser::NetworkReadExt};

#[java_packet(LOGIN_KEY)]
pub struct SEncryptionResponse {
    pub shared_secret: Box<[u8]>,
    pub verify_token: Box<[u8]>,
}

impl ServerPacket for SEncryptionResponse {
    fn read(mut read: impl Read, _version: &MinecraftVersion) -> Result<Self, ReadingError> {
        // Both fields are RSA-encrypted with our 1024 bit key (128 byte ciphertexts); leave
        // headroom for larger keys but never accept kilobytes.
        const MAX_ENCRYPTED_LENGTH: usize = 512;

        let shared_secret_length = read.get_var_int()?.0 as usize;
        if shared_secret_length > MAX_ENCRYPTED_LENGTH {
            return Err(ReadingError::TooLarge("shared secret".to_string()));
        }
        let shared_secret = read.read_boxed_slice(shared_secret_length)?;
        let verify_token_length = read.get_var_int()?.0 as usize;
        if verify_token_length > MAX_ENCRYPTED_LENGTH {
            return Err(ReadingError::TooLarge("verify token".to_string()));
        }
        let verify_token = read.read_boxed_slice(verify_token_length)?;
        Ok(Self {
            shared_secret,
            verify_token,
        })
    }
}
