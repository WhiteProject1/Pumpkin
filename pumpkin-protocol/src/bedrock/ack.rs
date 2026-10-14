use std::io::{Error, ErrorKind, Read, Write};

use pumpkin_macros::packet;

const MAX_ACK_RECORDS: u16 = 4096;

use crate::{
    codec::u24,
    serial::{PacketRead, PacketWrite},
};

#[packet(0xC0)]
pub struct Ack {
    /// Inclusive `(start, end)` sequence number ranges.
    ///
    /// Ranges are kept as sent instead of being expanded so that a single
    /// datagram cannot make the server allocate millions of sequence numbers.
    ranges: Vec<(u32, u32)>,
}

impl Ack {
    #[must_use]
    pub fn new(sequences: Vec<u32>) -> Self {
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        for seq in sequences {
            match ranges.last_mut() {
                Some((_, end)) if end.checked_add(1) == Some(seq) => *end = seq,
                _ => ranges.push((seq, seq)),
            }
        }
        Self { ranges }
    }

    fn write_range<W: Write>(start: u32, end: u32, writer: &mut W) -> Result<(), Error> {
        if start == end {
            1u8.write(writer)?;
            u24(start).write(writer)
        } else {
            0u8.write(writer)?;
            u24(start).write(writer)?;
            u24(end).write(writer)
        }
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let size = u16::read_be(reader)?;

        if size > MAX_ACK_RECORDS {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ACK packet range is too large.",
            ));
        }

        let mut ranges = Vec::with_capacity(size as usize);
        for _ in 0..size {
            let single = bool::read(reader)?;
            let start = u24::read(reader)?.0;
            let end = if single { start } else { u24::read(reader)?.0 };
            if end < start {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "ACK range ends before it starts.",
                ));
            }
            ranges.push((start, end));
        }
        Ok(Self { ranges })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        0xC0u8.write(writer)?;
        (self.ranges.len() as u16).write_be(writer)?;
        for &(start, end) in &self.ranges {
            Self::write_range(start, end, writer)?;
        }
        Ok(())
    }
}
