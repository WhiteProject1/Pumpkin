use std::string::FromUtf8Error;

use bytes::{BufMut, BytesMut};
use thiserror::Error;

/// The largest packet a client may send (as per the Source RCON protocol).
pub const MAX_PACKET_SIZE: usize = 1460;
/// Size of the fields that follow the length prefix: id (4) + type (4) + two NUL terminators.
const MIN_BODY_SIZE: usize = 10;

/// Client -> Server
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerboundPacket {
    /// Typically, the first packet sent by the client, which is used to authenticate the connection with the server.
    Auth = 3,
    /// This packet type represents a command issued by a client to the server. This can be a `ConCommand` such as /kill <player> or /weather clear.
    /// The response will vary depending on the command issued.
    ExecCommand = 2,
}

impl ServerboundPacket {
    pub const fn from_i32(n: i32) -> Option<Self> {
        match n {
            3 => Some(Self::Auth),
            2 => Some(Self::ExecCommand),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Server -> Client
pub enum ClientboundPacket {
    /// This packet is a notification of the connection's current auth status. When the server receives an auth request, it will respond with an empty `SERVERDATA_RESPONSE_VALUE`,
    /// followed immediately by a `SERVERDATA_AUTH_RESPONSE` indicating whether authentication succeeded or failed. Note that the status code is returned in the packet id field, so when pairing the response with the original auth request, you may need to look at the packet id of the `SERVERDATA_RESPONSE_VALUE`.
    AuthResponse = 2,
    /// A `SERVERDATA_RESPONSE` packet is the response to a `SERVERDATA_EXECCOMMAND` request.
    Output = 0,
}

impl ClientboundPacket {
    pub fn write_buf(self, id: i32, body: &str) -> BytesMut {
        // let len = outgoing.len() as u64;
        let mut buf = BytesMut::new();
        // 10 is for 4 bytes ty, 4 bytes id, and 2 terminating nul bytes.
        buf.put_i32_le(10 + body.len() as i32);
        buf.put_i32_le(id);
        buf.put_i32_le(self as i32);
        let bytes = body.as_bytes();
        buf.put_slice(bytes);
        buf.put_u8(0);
        buf.put_u8(0);
        buf
    }
}

#[derive(Error, Debug)]
pub enum PacketError {
    #[error("Invalid length")]
    InvalidLength,
    #[error("Unknown packet type {0}")]
    UnknownType(i32),
    #[error("Failed to read packet")]
    FailedRead(std::io::Error),
    #[error("Dailed to send packet")]
    FailedSend(std::io::Error),
    #[error("Invalid packet string body")]
    InvalidBody(FromUtf8Error),
    #[error("Packet body is not NUL terminated")]
    MissingTerminator,
}

#[derive(Debug)]
/// Serverbound packet
pub struct Packet {
    id: i32,
    ptype: ServerboundPacket,
    body: String,
}

impl Packet {
    /// Takes one complete packet off the front of `incoming`.
    ///
    /// Returns `Ok(None)` when the buffer does not hold a whole packet yet; the caller keeps the
    /// bytes and reads more.
    pub fn deserialize(incoming: &mut Vec<u8>) -> Result<Option<Self>, PacketError> {
        if incoming.len() < 4 {
            return Ok(None);
        }
        let declared = i32::from_le_bytes([incoming[0], incoming[1], incoming[2], incoming[3]]);
        // The length never includes itself. It must at least hold id, type and the two NULs and
        // never exceed the protocol maximum; everything else is garbage and we hang up.
        let Ok(declared) = usize::try_from(declared) else {
            return Err(PacketError::InvalidLength);
        };
        if !(MIN_BODY_SIZE..=MAX_PACKET_SIZE - 4).contains(&declared) {
            return Err(PacketError::InvalidLength);
        }
        let total = declared + 4;
        if incoming.len() < total {
            // Wait for the rest of the packet (it may be split across TCP segments).
            return Ok(None);
        }

        let id = i32::from_le_bytes([incoming[4], incoming[5], incoming[6], incoming[7]]);
        let ty = i32::from_le_bytes([incoming[8], incoming[9], incoming[10], incoming[11]]);
        let body = &incoming[12..total - 2];
        if incoming[total - 2] != 0 || incoming[total - 1] != 0 || body.contains(&0) {
            return Err(PacketError::MissingTerminator);
        }
        let ptype = ServerboundPacket::from_i32(ty).ok_or(PacketError::UnknownType(ty))?;
        let body = String::from_utf8(body.to_vec()).map_err(PacketError::InvalidBody)?;
        incoming.drain(..total);

        Ok(Some(Self { id, ptype, body }))
    }
    pub fn get_body(&self) -> &str {
        &self.body
    }

    pub const fn get_type(&self) -> ServerboundPacket {
        self.ptype
    }

    pub const fn get_id(&self) -> i32 {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(id: i32, ty: i32, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&((body.len() + 10) as i32).to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&ty.to_le_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn parses_a_complete_packet_and_leaves_the_rest() {
        let mut buf = encode(7, 3, b"secret");
        buf.extend_from_slice(&encode(8, 2, b"list"));
        let first = Packet::deserialize(&mut buf).unwrap().unwrap();
        assert_eq!(first.get_id(), 7);
        assert_eq!(first.get_type(), ServerboundPacket::Auth);
        assert_eq!(first.get_body(), "secret");
        let second = Packet::deserialize(&mut buf).unwrap().unwrap();
        assert_eq!(second.get_type(), ServerboundPacket::ExecCommand);
        assert_eq!(second.get_body(), "list");
        assert!(buf.is_empty());
    }

    #[test]
    fn waits_for_split_packets() {
        let full = encode(1, 3, b"password");
        let mut buf = full[..9].to_vec();
        assert!(Packet::deserialize(&mut buf).unwrap().is_none());
        buf.extend_from_slice(&full[9..]);
        assert!(Packet::deserialize(&mut buf).unwrap().is_some());
    }

    #[test]
    fn rejects_bad_lengths_and_types() {
        let mut buf = i32::MAX.to_le_bytes().to_vec();
        assert!(matches!(
            Packet::deserialize(&mut buf),
            Err(PacketError::InvalidLength)
        ));
        let mut buf = (-5i32).to_le_bytes().to_vec();
        assert!(matches!(
            Packet::deserialize(&mut buf),
            Err(PacketError::InvalidLength)
        ));
        let mut buf = encode(1, 9, b"x");
        assert!(matches!(
            Packet::deserialize(&mut buf),
            Err(PacketError::UnknownType(9))
        ));
        let mut buf = encode(1, 2, b"x");
        let len = buf.len();
        buf[len - 1] = 1;
        assert!(matches!(
            Packet::deserialize(&mut buf),
            Err(PacketError::MissingTerminator)
        ));
    }
}
