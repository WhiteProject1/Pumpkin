use std::net::SocketAddr;

use pumpkin_macros::packet;

use crate::{bedrock::RakNetMagic, serial::PacketRead};

#[derive(PacketRead)]
#[packet(0x05)]
/// The client sends this when attempting to join the server
pub struct SOpenConnectionRequest1 {
    pub magic: RakNetMagic,
    pub protocol_version: u8,
    #[serial(big_endian)]
    pub mtu: u16,
}

#[derive(PacketRead)]
#[packet(0x07)]
pub struct SOpenConnectionRequest2 {
    pub magic: RakNetMagic,
    pub server_address: SocketAddr,
    #[serial(big_endian)]
    pub mtu: u16,
    #[serial(big_endian)]
    pub client_guid: u64,
}
