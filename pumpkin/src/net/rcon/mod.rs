use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use packet::{ClientboundPacket, Packet, PacketError, ServerboundPacket};
use pumpkin_config::RCONConfig;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    sync::Mutex,
};
use tracing::{debug, error, info, warn};

use crate::{SHOULD_STOP, STOP_INTERRUPT, server::Server};

mod packet;

/// How long an unauthenticated client may stay connected without sending a valid login.
const PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Unparsed bytes we are willing to buffer for one client. A valid packet is at most
/// [`packet::MAX_PACKET_SIZE`] bytes, so anything beyond a few packets is garbage.
const MAX_INCOMING_BUFFER: usize = 4 * packet::MAX_PACKET_SIZE;
/// After this many failed logins an address is refused for [`LOGIN_BAN_DURATION`].
const MAX_FAILED_LOGINS: u32 = 5;
const LOGIN_BAN_DURATION: Duration = Duration::from_secs(5 * 60);

pub struct LoginFailures {
    count: u32,
    last: Instant,
}

pub type FailedLogins = Arc<Mutex<HashMap<IpAddr, LoginFailures>>>;

/// Decrements the live connection counter when the connection task ends.
struct ConnectionGuard(Arc<AtomicU32>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct RCONServer;

impl RCONServer {
    pub async fn run(config: &RCONConfig, server: Arc<Server>) -> Result<(), std::io::Error> {
        if config.password.is_empty() {
            error!(
                "RCON is enabled but `password` is empty; refusing to start RCON. Set a password in the networking config."
            );
            return Ok(());
        }

        let listener = tokio::net::TcpListener::bind(config.address).await?;

        let password: Arc<str> = Arc::from(config.password.as_str());
        let connections = Arc::new(AtomicU32::new(0));
        let failed_logins: FailedLogins = Arc::new(Mutex::new(HashMap::new()));

        while !SHOULD_STOP.load(Ordering::Relaxed) {
            let await_new_client = || async {
                let t1 = listener.accept();
                let t2 = STOP_INTERRUPT.cancelled();

                select! {
                    client = t1 => Some(client),
                    () = t2 => None,
                }
            };
            // Asynchronously wait for an inbound socket.

            let Some(result) = await_new_client().await else {
                break;
            };
            let (connection, address) = match result {
                Ok(accepted) => accepted,
                Err(e) => {
                    // e.g. EMFILE: don't let a transient accept error take the listener down.
                    error!("Failed to accept RCON connection: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            if config.max_connections != 0
                && connections.load(Ordering::Relaxed) >= config.max_connections
            {
                debug!("RCON ({address}): connection limit reached, dropping connection");
                continue;
            }

            if Self::is_login_banned(&failed_logins, address.ip()).await {
                debug!("RCON ({address}): too many failed logins, dropping connection");
                continue;
            }

            connections.fetch_add(1, Ordering::Relaxed);
            let guard = ConnectionGuard(connections.clone());
            let mut client = RCONClient::new(connection, address);

            let password = password.clone();
            let server = server.clone();
            let failed_logins = failed_logins.clone();
            tokio::spawn(async move {
                let _guard = guard;
                while !client.handle(&server, &password, &failed_logins).await {}
                debug!("closed RCON connection");
            });
        }
        Ok(())
    }

    async fn is_login_banned(failed_logins: &FailedLogins, ip: IpAddr) -> bool {
        let mut failures = failed_logins.lock().await;
        failures.retain(|_, entry| entry.last.elapsed() < LOGIN_BAN_DURATION);
        failures
            .get(&ip)
            .is_some_and(|entry| entry.count >= MAX_FAILED_LOGINS)
    }
}

pub struct RCONClient {
    connection: tokio::net::TcpStream,
    address: SocketAddr,
    logged_in: bool,
    incoming: Vec<u8>,
    closed: bool,
}

impl RCONClient {
    #[must_use]
    pub const fn new(connection: tokio::net::TcpStream, address: SocketAddr) -> Self {
        Self {
            connection,
            address,
            logged_in: false,
            incoming: Vec::new(),
            closed: false,
        }
    }

    /// Returns whether the client is closed or not.
    pub async fn handle(
        &mut self,
        server: &Arc<Server>,
        password: &str,
        failed_logins: &FailedLogins,
    ) -> bool {
        if !self.closed {
            let read = if self.logged_in {
                self.read_bytes().await
            } else {
                match tokio::time::timeout(PRE_AUTH_TIMEOUT, self.read_bytes()).await {
                    Ok(read) => read,
                    Err(_) => {
                        debug!("RCON ({}): no login within timeout", self.address);
                        return true;
                    }
                }
            };
            match read {
                // The stream is closed, so we can't reply, so we just close everything.
                Ok(true) => return true,
                Ok(false) => {}
                Err(e) => {
                    error!("Could not read packet: {e}");
                    return true;
                }
            }
            if self.incoming.len() > MAX_INCOMING_BUFFER {
                warn!(
                    "RCON ({}): client sent {} bytes without a valid packet, closing",
                    self.address,
                    self.incoming.len()
                );
                return true;
            }

            // Handle every complete packet in the buffer, not just the first one, so unparsed
            // data can't pile up.
            while !self.closed {
                let packet = match self.receive_packet() {
                    Ok(Some(packet)) => packet,
                    Ok(None) => break,
                    Err(e) => {
                        error!("RCON ({}): {e}", self.address);
                        self.closed = true;
                        break;
                    }
                };
                // If we get a close here, we might have a reply, which we still want to write.
                if let Err(e) = self
                    .poll(server, password, failed_logins, packet)
                    .await
                {
                    error!("RCON error: {e}");
                    self.closed = true;
                }
            }
        }
        self.closed
    }

    async fn poll(
        &mut self,
        server: &Arc<Server>,
        password: &str,
        failed_logins: &FailedLogins,
        packet: Packet,
    ) -> Result<(), PacketError> {
        let config = &server.advanced_config.networking.rcon;
        match packet.get_type() {
            ServerboundPacket::Auth => {
                if password_matches(packet.get_body(), password) {
                    self.send(ClientboundPacket::AuthResponse, packet.get_id(), "")
                        .await?;
                    if config.logging.logged_successfully {
                        info!("RCON ({}): Client logged in successfully", self.address);
                    }
                    failed_logins.lock().await.remove(&self.address.ip());
                    self.logged_in = true;
                } else {
                    if config.logging.wrong_password {
                        info!("RCON ({}): Client tried the wrong password", self.address);
                    }
                    Self::record_failed_login(failed_logins, self.address.ip()).await;
                    self.send(ClientboundPacket::AuthResponse, -1, "").await?;
                    self.closed = true;
                }
            }
            ServerboundPacket::ExecCommand => {
                if self.logged_in {
                    let output = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));

                    let server_clone = server.clone();
                    let output_clone = output.clone();
                    let packet_body = packet.get_body().to_owned();

                    // Wait task complete before send output
                    let _ = tokio::spawn(async move {
                        server_clone
                            .command_dispatcher
                            .read()
                            .await
                            .handle_command(
                                &crate::command::CommandSender::Rcon(output_clone),
                                &server_clone,
                                &packet_body,
                            )
                            .await;
                    })
                    .await;

                    let output = output.lock().await;
                    for line in output.iter() {
                        if config.logging.commands {
                            info!("RCON ({}): {}", self.address, line);
                        }
                        self.send(ClientboundPacket::Output, packet.get_id(), line)
                            .await?;
                    }
                } else {
                    // Commands before a successful login: tell the client and hang up.
                    self.send(ClientboundPacket::AuthResponse, -1, "").await?;
                    self.closed = true;
                }
            }
        }
        Ok(())
    }

    async fn record_failed_login(failed_logins: &FailedLogins, ip: IpAddr) {
        let mut failures = failed_logins.lock().await;
        let entry = failures.entry(ip).or_insert(LoginFailures {
            count: 0,
            last: Instant::now(),
        });
        entry.count = entry.count.saturating_add(1);
        entry.last = Instant::now();
    }

    async fn read_bytes(&mut self) -> std::io::Result<bool> {
        let mut buf = [0; packet::MAX_PACKET_SIZE];
        let n = self.connection.read(&mut buf).await?;
        if n == 0 {
            return Ok(true);
        }
        self.incoming.extend_from_slice(&buf[..n]);
        Ok(false)
    }

    async fn send(
        &mut self,
        packet: ClientboundPacket,
        id: i32,
        body: &str,
    ) -> Result<(), PacketError> {
        let buf = packet.write_buf(id, body);
        self.connection
            .write_all(&buf)
            .await
            .map_err(PacketError::FailedSend)?;
        Ok(())
    }

    fn receive_packet(&mut self) -> Result<Option<Packet>, PacketError> {
        Packet::deserialize(&mut self.incoming)
    }
}

/// Compares the supplied password against the configured one in constant time (hashing both
/// first so neither the length nor the position of the first mismatch leaks through timing).
fn password_matches(supplied: &str, expected: &str) -> bool {
    let supplied = Sha256::digest(supplied.as_bytes());
    let expected = Sha256::digest(expected.as_bytes());
    supplied
        .iter()
        .zip(expected.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::password_matches;

    #[test]
    fn password_compare() {
        assert!(password_matches("hunter2", "hunter2"));
        assert!(!password_matches("hunter", "hunter2"));
        assert!(!password_matches("", "hunter2"));
        assert!(!password_matches("hunter2", ""));
    }
}
