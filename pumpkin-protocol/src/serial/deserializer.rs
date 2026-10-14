use std::{
    io::{Error, ErrorKind, Read},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use pumpkin_util::math::{vector2::Vector2, vector3::Vector3};
use uuid::Uuid;

use crate::{codec::var_uint::VarUInt, serial::PacketRead};

/// Largest byte array / string a single Bedrock packet may carry. The length prefix is client
/// controlled, so it must never be trusted for allocation on its own.
pub const MAX_BYTES_LEN: usize = 2 * 1024 * 1024;

impl PacketRead for bool {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0];
        reader.read_exact(&mut buf)?;
        Ok(buf[0] != 0)
    }
}

impl PacketRead for i8 {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0];
        reader.read_exact(&mut buf)?;
        Ok(buf[0] as Self)
    }
}

impl PacketRead for i16 {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0; size_of::<Self>()];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }
}

impl PacketRead for i32 {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0; size_of::<Self>()];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }

    fn read_be<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0; size_of::<Self>()];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_be_bytes(buf))
    }
}

impl PacketRead for i64 {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0; size_of::<Self>()];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }
}

impl PacketRead for u8 {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0];
        reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }
}

impl PacketRead for u16 {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0; size_of::<Self>()];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }

    fn read_be<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0; size_of::<Self>()];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_be_bytes(buf))
    }
}

impl PacketRead for u32 {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0; size_of::<Self>()];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }

    fn read_be<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0; size_of::<Self>()];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_be_bytes(buf))
    }
}

impl PacketRead for u64 {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0; size_of::<Self>()];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }

    fn read_be<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0; size_of::<Self>()];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_be_bytes(buf))
    }
}

impl PacketRead for f32 {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0; size_of::<Self>()];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }
}

impl PacketRead for f64 {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0; size_of::<Self>()];
        reader.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }
}

impl<T: PacketRead, const N: usize> PacketRead for [T; N] {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        // Read into a Vec first so a failure part way through never leaves (or drops)
        // uninitialized elements.
        let mut items = Vec::with_capacity(N);
        for _ in 0..N {
            items.push(T::read(reader)?);
        }
        items
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "array length mismatch"))
    }
}

impl PacketRead for String {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let vec = Vec::read(reader)?;
        Self::from_utf8(vec).map_err(|_| Error::new(ErrorKind::InvalidData, "invalid UTF-8"))
    }
}

impl PacketRead for Vec<u8> {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let len = VarUInt::read(reader)?.0 as usize;
        if len > MAX_BYTES_LEN {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("byte array length {len} exceeds {MAX_BYTES_LEN}"),
            ));
        }
        // Grow with the data that actually arrives instead of trusting the declared length.
        let mut buf = Self::new();
        reader.take(len as u64).read_to_end(&mut buf)?;
        if buf.len() != len {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!("expected {len} bytes but only {} were available", buf.len()),
            ));
        }
        Ok(buf)
    }
}

impl<T: PacketRead> PacketRead for Vector3<T> {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(Self {
            x: T::read(reader)?,
            y: T::read(reader)?,
            z: T::read(reader)?,
        })
    }
}

impl<T: PacketRead> PacketRead for Vector2<T> {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(Self {
            x: T::read(reader)?,
            y: T::read(reader)?,
        })
    }
}

impl PacketRead for SocketAddr {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        match u8::read(reader)? {
            4 => {
                let ip = u32::read_be(reader)?;
                let port = u16::read_be(reader)?;
                Ok(Self::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }
            6 => {
                // Addr family
                u16::read(reader)?;
                let port = u16::read_be(reader)?;
                let flowinfo = u32::read_be(reader)?;

                let mut ip = [0; 16];
                reader.read_exact(&mut ip)?;
                let ip = Ipv6Addr::from(ip);

                let scope_id = u32::read_be(reader)?;

                Ok(Self::V6(SocketAddrV6::new(ip, port, flowinfo, scope_id)))
            }
            _ => Err(Error::other("Invalid socket address version")),
        }
    }
}

impl PacketRead for Uuid {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut bytes = [0; 16];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_bytes(bytes))
    }
}

impl<T: PacketRead> PacketRead for Option<T> {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        bool::read(reader)?.then(|| T::read(reader)).transpose()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::serial::{PacketRead, PacketWrite};

    use super::MAX_BYTES_LEN;

    #[test]
    fn byte_vec_rejects_huge_declared_length() {
        // VarUInt(u32::MAX) followed by nothing: must error, must not allocate 4 GiB.
        let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
        assert!(Vec::<u8>::read(&mut Cursor::new(bytes)).is_err());
    }

    #[test]
    fn byte_vec_rejects_truncated_payload() {
        let mut bytes = Vec::new();
        crate::codec::var_uint::VarUInt(10).write(&mut bytes).unwrap();
        bytes.extend_from_slice(&[1, 2, 3]);
        assert!(Vec::<u8>::read(&mut Cursor::new(bytes)).is_err());
    }

    #[test]
    fn string_rejects_invalid_utf8() {
        let mut bytes = Vec::new();
        crate::codec::var_uint::VarUInt(2).write(&mut bytes).unwrap();
        bytes.extend_from_slice(&[0xC3, 0x28]);
        assert!(String::read(&mut Cursor::new(bytes)).is_err());
    }

    #[test]
    fn string_roundtrip() {
        let mut bytes = Vec::new();
        "héllo".to_string().write(&mut bytes).unwrap();
        assert_eq!(String::read(&mut Cursor::new(bytes)).unwrap(), "héllo");
        assert!(MAX_BYTES_LEN > 0);
    }

    #[test]
    fn fixed_array_short_read_is_an_error() {
        let bytes = [1u8, 2, 3];
        assert!(<[u8; 16]>::read(&mut Cursor::new(bytes)).is_err());
        let bytes = [1u8, 2, 3, 4];
        assert_eq!(<[u8; 4]>::read(&mut Cursor::new(bytes)).unwrap(), [1, 2, 3, 4]);
    }
}
