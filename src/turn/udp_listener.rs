// UDP TURN listener
//
// Listens on a UDP socket for incoming STUN/TURN messages and ChannelData.
// Dispatches to the TurnHandler for processing and executes the resulting
// I/O actions (send responses, relay data to peers).
//
// Also manages relay receiver tasks — when a new allocation is created,
// a task is spawned to read data arriving on the allocation's relay socket
// from peers. That data is wrapped as either ChannelData (if a channel
// binding exists) or a STUN Data indication, and sent back to the client
// via the main UDP socket.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use super::allocation::{AllocationManager, FiveTuple, TransportProtocol};
use super::attributes::StunAttribute;
use super::handler::{HandleResult, MessageContext, TurnHandler};
use super::stun::{
    is_channel_data, is_stun_message, ChannelData, Class, MessageType, Method, StunMessage,
    compute_fingerprint,
};

// ---------------------------------------------------------------------------
// UdpTurnListener
// ---------------------------------------------------------------------------

/// UDP listener for the TURN server.
///
/// Reads datagrams from the primary UDP socket, dispatches them to the
/// [`TurnHandler`], and executes I/O actions. Also spawns relay receiver
/// tasks for each new allocation.
pub struct UdpTurnListener {
    /// The primary UDP socket bound to the TURN server port (e.g., 3478).
    socket: Arc<UdpSocket>,
    /// The shared TURN message handler.
    handler: Arc<TurnHandler>,
    /// The allocation manager (needed for relay receiver lookups).
    allocations: Arc<AllocationManager>,
    /// The server's listen address.
    server_addr: SocketAddr,
    /// The server's public IP (for MessageContext).
    server_public_ip: std::net::IpAddr,
}

impl UdpTurnListener {
    /// Create a new UDP TURN listener.
    ///
    /// - `socket`: The primary UDP socket (already bound to the listen address).
    /// - `handler`: The shared TURN message handler.
    /// - `allocations`: The shared allocation manager.
    /// - `server_addr`: The server's listen address.
    /// - `server_public_ip`: The server's public IP for relay addresses.
    pub fn new(
        socket: Arc<UdpSocket>,
        handler: Arc<TurnHandler>,
        allocations: Arc<AllocationManager>,
        server_addr: SocketAddr,
        server_public_ip: std::net::IpAddr,
    ) -> Self {
        Self {
            socket,
            handler,
            allocations,
            server_addr,
            server_public_ip,
        }
    }

    /// Run the UDP listener loop.
    ///
    /// This reads datagrams from the primary UDP socket in a loop. Each
    /// incoming message is dispatched to a spawned task for processing,
    /// so the receive loop is never blocked by handler logic.
    ///
    /// When the handler returns an [`HandleResult::AllocationCreated`], this
    /// also spawns a relay receiver task for the new allocation's relay socket.
    pub async fn run(self: Arc<Self>) {
        let mut buf = vec![0u8; 65536]; // 64KB max UDP datagram

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    let data = buf[..len].to_vec();
                    let this = Arc::clone(&self);
                    // Spawn a task per message to avoid blocking the receive loop
                    tokio::spawn(async move {
                        this.process_message(&data, client_addr).await;
                    });
                }
                Err(e) => {
                    log::error!("[TURN-UDP] recv error: {}", e);
                    // Brief sleep to avoid tight error loop
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Process a single incoming UDP message.
    ///
    /// Determines whether the message is ChannelData or a STUN message,
    /// dispatches to the handler, and executes the resulting actions.
    async fn process_message(&self, data: &[u8], client_addr: SocketAddr) {
        let ctx = MessageContext {
            client_addr,
            server_addr: self.server_addr,
            protocol: TransportProtocol::Udp,
            server_public_ip: self.server_public_ip,
        };

        if is_channel_data(data) {
            // Parse ChannelData and handle
            match ChannelData::decode(data) {
                Ok(channel_data) => {
                    if let Some(result) = self.handler.handle_channel_data(&channel_data, &ctx).await
                    {
                        self.execute_result(result, client_addr).await;
                    }
                }
                Err(e) => {
                    log::debug!(
                        "[TURN-UDP] failed to parse ChannelData from {}: {}",
                        client_addr,
                        e
                    );
                }
            }
        } else if is_stun_message(data) {
            // Parse STUN message and handle
            match StunMessage::decode(data) {
                Ok(msg) => {
                    let results = self.handler.handle_message(&msg, &ctx).await;
                    for result in results {
                        self.execute_result(result, client_addr).await;
                    }
                }
                Err(e) => {
                    log::debug!(
                        "[TURN-UDP] failed to parse STUN message from {}: {}",
                        client_addr,
                        e
                    );
                }
            }
        }
        // else: unknown message format, silently ignored
    }

    /// Execute a single [`HandleResult`] action.
    ///
    /// Sends responses to clients, relays data to peers, and spawns relay
    /// receiver tasks for new allocations.
    async fn execute_result(&self, result: HandleResult, client_addr: SocketAddr) {
        match result {
            HandleResult::Response(data) => {
                if let Err(e) = self.socket.send_to(&data, client_addr).await {
                    log::error!(
                        "[TURN-UDP] failed to send response to {}: {}",
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
                if let Err(e) = relay_socket.send_to(&data, peer_addr).await {
                    log::error!(
                        "[TURN-UDP] failed to relay to peer {}: {}",
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
                        "[TURN-UDP] failed to send channel data to peer {}: {}",
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
                // Send the success response to the client
                if let Err(e) = self.socket.send_to(&response, client_addr).await {
                    log::error!(
                        "[TURN-UDP] failed to send allocate response to {}: {}",
                        client_addr,
                        e
                    );
                }

                // Spawn a relay receiver task for this allocation
                let main_socket = Arc::clone(&self.socket);
                let allocations = Arc::clone(&self.allocations);
                let ft = five_tuple.clone();
                log::debug!(
                    "[TURN-UDP] spawning relay receiver for {} (relay {})",
                    client_addr,
                    relay_addr
                );
                tokio::spawn(async move {
                    relay_receiver_task(
                        relay_socket,
                        relay_addr,
                        ft,
                        main_socket,
                        allocations,
                    )
                    .await;
                });
            }
            HandleResult::None => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Relay receiver task
// ---------------------------------------------------------------------------

/// Relay receiver task for a single allocation.
///
/// Reads data arriving on the allocation's relay socket from peers and
/// forwards it to the client. The data is wrapped as:
/// - **ChannelData** if there's a channel binding for the peer address
/// - **STUN Data indication** otherwise (with XOR-PEER-ADDRESS and DATA)
///
/// The task runs until the relay socket encounters an unrecoverable error
/// or the allocation is cleaned up (at which point recv_from will fail
/// because the socket is dropped).
///
/// This function is `pub` so it can be reused by the TCP listener for
/// TCP-originated allocations that still use UDP relay sockets.
pub async fn relay_receiver_task(
    relay_socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    five_tuple: FiveTuple,
    main_socket: Arc<UdpSocket>,
    allocations: Arc<AllocationManager>,
) {
    let mut buf = vec![0u8; 65536];
    let client_addr = five_tuple.client_addr;

    loop {
        match relay_socket.recv_from(&mut buf).await {
            Ok((len, peer_addr)) => {
                let data = &buf[..len];

                // Check that a permission exists for this peer's IP
                if !allocations
                    .has_permission(&five_tuple, &peer_addr.ip())
                    .await
                {
                    log::debug!(
                        "[TURN-RELAY] dropping packet from {} to relay {}: no permission",
                        peer_addr,
                        relay_addr
                    );
                    continue;
                }

                // Check if there's a channel binding for this peer
                let wrapped = if let Some(channel_number) = allocations
                    .get_channel_for_peer(&five_tuple, &peer_addr)
                    .await
                {
                    // Wrap as ChannelData
                    let cd = ChannelData {
                        channel_number,
                        data: data.to_vec(),
                    };
                    cd.encode()
                } else {
                    // Wrap as a STUN Data indication
                    build_data_indication(peer_addr, data)
                };

                // Send to the client via the main UDP socket
                if let Err(e) = main_socket.send_to(&wrapped, client_addr).await {
                    log::error!(
                        "[TURN-RELAY] failed to send to client {}: {}",
                        client_addr,
                        e
                    );
                }
            }
            Err(e) => {
                // Socket error — likely the allocation was cleaned up and the
                // socket was dropped. Exit the task.
                log::debug!(
                    "[TURN-RELAY] relay socket {} recv error (allocation likely expired): {}",
                    relay_addr,
                    e
                );
                break;
            }
        }
    }

    log::debug!(
        "[TURN-RELAY] relay receiver task for {} exiting",
        relay_addr
    );
}

/// Build a STUN Data indication message (Method::Data, Class::Indication)
/// with XOR-PEER-ADDRESS and DATA attributes.
///
/// Data indications are used when there's no channel binding for the peer.
/// Per RFC 5766 §10.3, they don't require MESSAGE-INTEGRITY.
fn build_data_indication(peer_addr: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut msg = StunMessage::new_random(MessageType::new(Method::Data, Class::Indication));

    msg.add_attribute(StunAttribute::XorPeerAddress(peer_addr));
    msg.add_attribute(StunAttribute::Data(data.to_vec()));

    // Add FINGERPRINT for demultiplexing
    let fp_bytes = msg.encode_for_fingerprint();
    let fingerprint = compute_fingerprint(&fp_bytes);
    msg.add_attribute(StunAttribute::Fingerprint(fingerprint));

    msg.encode()
}
