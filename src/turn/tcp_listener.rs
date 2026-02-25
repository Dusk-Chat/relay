// TCP TURN listener
//
// Accepts TCP connections from TURN clients and frames STUN/ChannelData
// messages over the stream. Per RFC 5766 §2.1, when TURN is used over
// TCP, the client connects to the TURN server via TCP but the relay
// still uses UDP to communicate with peers.
//
// TCP framing: STUN messages and ChannelData are self-delimiting on
// a TCP stream. The reader peeks at the first two bytes to determine
// the message type:
// - If the first two bits are 00 → STUN message. Read 20-byte header,
//   extract message length from bytes 2-3, then read the attribute body.
// - Otherwise → ChannelData. The first 2 bytes are the channel number,
//   next 2 bytes are the data length, then read the data (padded to 4 bytes).

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::allocation::{AllocationManager, TransportProtocol};
use super::handler::{HandleResult, MessageContext, TurnHandler};
use super::stun::{is_channel_data, ChannelData, StunMessage};

// ---------------------------------------------------------------------------
// TcpTurnListener
// ---------------------------------------------------------------------------

/// TCP listener for the TURN server.
///
/// Accepts TCP connections from clients and processes STUN/TURN messages
/// framed on the TCP stream. Each accepted connection is handled in a
/// separate spawned task.
pub struct TcpTurnListener {
    /// The bound TCP listener.
    listener: TcpListener,
    /// The shared TURN message handler.
    handler: Arc<TurnHandler>,
    /// The shared allocation manager (for relay receiver spawning).
    allocations: Arc<AllocationManager>,
    /// The server's listen address.
    server_addr: SocketAddr,
    /// The server's public IP (for MessageContext).
    server_public_ip: std::net::IpAddr,
    /// The primary UDP socket (for spawning relay receiver tasks).
    /// TCP clients still use UDP relay sockets for the peer-facing side.
    udp_socket: Option<Arc<tokio::net::UdpSocket>>,
}

impl TcpTurnListener {
    /// Bind a TCP listener on the given address.
    pub async fn bind(
        addr: SocketAddr,
        handler: Arc<TurnHandler>,
        allocations: Arc<AllocationManager>,
        server_public_ip: std::net::IpAddr,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let server_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            handler,
            allocations,
            server_addr,
            server_public_ip,
            udp_socket: None,
        })
    }

    /// Set the primary UDP socket (used for relay receiver tasks spawned
    /// from TCP-originated allocations).
    pub fn set_udp_socket(&mut self, socket: Arc<tokio::net::UdpSocket>) {
        self.udp_socket = Some(socket);
    }

    /// Run the TCP listener loop.
    ///
    /// Accepts connections in a loop and spawns a handler task for each one.
    pub async fn run(self) {
        let handler = self.handler;
        let server_addr = self.server_addr;
        let server_public_ip = self.server_public_ip;
        let allocations = self.allocations;
        let udp_socket = self.udp_socket;

        loop {
            match self.listener.accept().await {
                Ok((stream, client_addr)) => {
                    let handler = Arc::clone(&handler);
                    let allocations = Arc::clone(&allocations);
                    let udp_socket = udp_socket.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_client(
                            stream,
                            client_addr,
                            server_addr,
                            server_public_ip,
                            handler,
                            allocations,
                            udp_socket,
                        )
                        .await
                        {
                            log::debug!("[TURN-TCP] client {} disconnected: {}", client_addr, e);
                        }
                    });
                }
                Err(e) => {
                    log::error!("[TURN-TCP] accept error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-client TCP handler
// ---------------------------------------------------------------------------

/// Handle a single TCP client connection.
///
/// Reads STUN/ChannelData messages from the TCP stream in a loop, dispatches
/// them to the handler, and writes responses back.
async fn handle_tcp_client(
    stream: TcpStream,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    server_public_ip: std::net::IpAddr,
    handler: Arc<TurnHandler>,
    allocations: Arc<AllocationManager>,
    udp_socket: Option<Arc<tokio::net::UdpSocket>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ctx = MessageContext {
        client_addr,
        server_addr,
        protocol: TransportProtocol::Tcp,
        server_public_ip,
    };

    let (mut reader, mut writer) = stream.into_split();
    let mut header_buf = [0u8; 4];

    loop {
        // Read the first 2 bytes to determine message type
        match reader.read_exact(&mut header_buf[..2]).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Clean disconnect
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }

        if is_channel_data(&header_buf[..2]) {
            // ChannelData: first 2 bytes = channel number, next 2 = data length
            reader.read_exact(&mut header_buf[2..4]).await?;
            let data_len = u16::from_be_bytes([header_buf[2], header_buf[3]]) as usize;

            // TCP pads ChannelData to 4-byte boundary
            let padded_len = (data_len + 3) & !3;
            let mut data_buf = vec![0u8; padded_len];
            reader.read_exact(&mut data_buf[..padded_len]).await?;

            // Reconstruct the full ChannelData for decoding (header + unpadded data)
            let mut full_msg = Vec::with_capacity(4 + data_len);
            full_msg.extend_from_slice(&header_buf);
            full_msg.extend_from_slice(&data_buf[..data_len]);

            match ChannelData::decode(&full_msg) {
                Ok(channel_data) => {
                    if let Some(result) =
                        handler.handle_channel_data(&channel_data, &ctx).await
                    {
                        execute_tcp_result(&mut writer, result, client_addr, &allocations, &udp_socket)
                            .await;
                    }
                }
                Err(e) => {
                    log::debug!(
                        "[TURN-TCP] failed to parse ChannelData from {}: {}",
                        client_addr,
                        e
                    );
                }
            }
        } else {
            // STUN message: first 2 bytes are message type, next 2 are message length
            // We need to read the remaining 18 bytes of the 20-byte header
            let mut stun_header = [0u8; 20];
            stun_header[0] = header_buf[0];
            stun_header[1] = header_buf[1];
            reader.read_exact(&mut stun_header[2..20]).await?;

            let msg_len = u16::from_be_bytes([stun_header[2], stun_header[3]]) as usize;

            // Read the attribute body
            let mut msg_buf = Vec::with_capacity(20 + msg_len);
            msg_buf.extend_from_slice(&stun_header);
            if msg_len > 0 {
                let mut body = vec![0u8; msg_len];
                reader.read_exact(&mut body).await?;
                msg_buf.extend_from_slice(&body);
            }

            match StunMessage::decode(&msg_buf) {
                Ok(msg) => {
                    let results = handler.handle_message(&msg, &ctx).await;
                    for result in results {
                        execute_tcp_result(&mut writer, result, client_addr, &allocations, &udp_socket)
                            .await;
                    }
                }
                Err(e) => {
                    log::debug!(
                        "[TURN-TCP] failed to parse STUN message from {}: {}",
                        client_addr,
                        e
                    );
                }
            }
        }
    }
}

/// Execute a single [`HandleResult`] for a TCP client.
///
/// Responses are written directly to the TCP stream. Relay operations
/// use the UDP relay socket (relay is always UDP, even for TCP clients).
async fn execute_tcp_result(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    result: HandleResult,
    client_addr: SocketAddr,
    allocations: &Arc<AllocationManager>,
    udp_socket: &Option<Arc<tokio::net::UdpSocket>>,
) {
    match result {
        HandleResult::Response(data) => {
            if let Err(e) = writer.write_all(&data).await {
                log::error!(
                    "[TURN-TCP] failed to write response to {}: {}",
                    client_addr,
                    e
                );
            }
        }
        HandleResult::RelayToPeer {
            peer_addr,
            data,
            relay_socket,
        } => {
            // Relay is always UDP even for TCP clients
            if let Err(e) = relay_socket.send_to(&data, peer_addr).await {
                log::error!(
                    "[TURN-TCP] failed to relay to peer {}: {}",
                    peer_addr,
                    e
                );
            }
        }
        HandleResult::ChannelDataToPeer {
            peer_addr,
            data,
            relay_socket,
        } => {
            if let Err(e) = relay_socket.send_to(&data, peer_addr).await {
                log::error!(
                    "[TURN-TCP] failed to send channel data to peer {}: {}",
                    peer_addr,
                    e
                );
            }
        }
        HandleResult::AllocationCreated {
            response,
            relay_socket,
            relay_addr,
            five_tuple,
        } => {
            // Send the success response to the TCP client
            if let Err(e) = writer.write_all(&response).await {
                log::error!(
                    "[TURN-TCP] failed to write allocate response to {}: {}",
                    client_addr,
                    e
                );
            }

            // For TCP clients, we still need a relay receiver task to handle
            // peer → relay socket → client. However, for TCP the data needs to
            // go back over the TCP stream. For simplicity, if a UDP socket is
            // available we use the UDP-based relay receiver. In a full
            // implementation, the relay receiver would write to the TCP stream.
            //
            // NOTE: In the current architecture, TCP allocations still relay
            // data via UDP. Peer data arriving on the relay socket will be
            // forwarded to the client's address via the main UDP socket (if
            // the client also has a UDP path). For pure TCP clients, a more
            // sophisticated approach would be needed.
            if let Some(main_udp) = udp_socket {
                let main_socket = Arc::clone(main_udp);
                let allocs = Arc::clone(allocations);
                let ft = five_tuple.clone();
                log::debug!(
                    "[TURN-TCP] spawning relay receiver for {} (relay {})",
                    client_addr,
                    relay_addr
                );
                tokio::spawn(async move {
                    super::udp_listener::relay_receiver_task(
                        relay_socket,
                        relay_addr,
                        ft,
                        main_socket,
                        allocs,
                    )
                    .await;
                });
            } else {
                log::warn!(
                    "[TURN-TCP] no UDP socket available for relay receiver (allocation {})",
                    relay_addr
                );
            }
        }
        HandleResult::None => {}
    }
}
