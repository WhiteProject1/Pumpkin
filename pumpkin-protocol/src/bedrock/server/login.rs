use pumpkin_macros::packet;
use std::io::{Error, ErrorKind, Read};

use crate::{codec::var_uint::VarUInt, serial::PacketRead};

/// Upper bound for each of the two length-prefixed token blobs in the login packet.
/// Real chains are a few KiB; the length is client-controlled and used for allocation.
const MAX_TOKEN_LEN: u32 = 64 * 1024;

#[packet(1)]
pub struct SLogin {
    // https://mojang.github.io/bedrock-protocol-docs/html/LoginPacket.html
    pub protocol_version: i32,

    // https://mojang.github.io/bedrock-protocol-docs/html/connectionRequest.html
    pub jwt: Vec<u8>,
    pub raw_token: Vec<u8>,
}

impl SLogin {
    fn read_token<R: Read>(reader: &mut R) -> Result<Vec<u8>, Error> {
        let len = u32::read(reader)?;
        if len > MAX_TOKEN_LEN {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Login token of {len} bytes exceeds the limit of {MAX_TOKEN_LEN} bytes"),
            ));
        }
        let mut token = vec![0; len as usize];
        reader.read_exact(&mut token)?;
        Ok(token)
    }
}

impl PacketRead for SLogin {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let protocol_version = i32::read_be(reader)?;
        let _len = VarUInt::read(reader)?;

        let jwt = Self::read_token(reader)?;
        let raw_token = Self::read_token(reader)?;

        Ok(Self {
            protocol_version,
            jwt,
            raw_token,
        })
    }
}
