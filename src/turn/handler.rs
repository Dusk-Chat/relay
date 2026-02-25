// TURN message handler per RFC 5766
//
// This is the core protocol logic that processes incoming STUN/TURN messages
// and produces response actions. It is completely I/O-free — the handler
// takes a parsed message + context and returns actions (response bytes,
// relay instructions) that the listener layer actually executes.
//
// Supported STUN/TURN methods:
//   - Binding Request (RFC 5389) — NAT discovery, no auth
//   - Allocate Request (RFC 5766 §6) — create relay allocation
//   - Refresh Request (RFC 5766 §7) — refresh/delete allocation
//   - CreatePermission Request (RFC 5766 §9) — install permissions
//   - ChannelBind Request (RFC 5766 §11) — bind channel to peer
//   - Send Indication (RFC 5766 §10) — relay data to peer
//   - ChannelData (RFC 5766 §11.4) — compact channel relay
//
// Authentication uses the long-term credential mechanism (RFC 5389 §10.2.2)
// with time-limited credentials per draft-uberti-behave-turn-rest-00.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;

use crate::turn::allocation::{
    AllocationManager, FiveTuple, TransportProtocol,
};
use crate::turn::attributes::StunAttribute;
use crate::turn::credentials::{
    compute_long_term_key, compute_message_integrity, compute_nonce,
    hmac_sha1, validate_message_integrity, validate_nonce,
};
use crate::turn::port_pool::PortPool;
use crate::turn::stun::{
    ChannelData, Class, MessageType, Method, StunMessage, compute_fingerprint,
};

// ---------------------------------------------------------------------------
// SOFTWARE attribute value
// ---------------------------------------------------------------------------

const SOFTWARE_NAME: &str = "Dusk TURN Server 0.1";

/// Maximum nonce age in seconds (10 minutes).
const NONCE_MAX_AGE_SECS: u64 = 600;

// ---------------------------------------------------------------------------
// MessageContext — transport-layer info for a received message
// ---------------------------------------------------------------------------

/// Context information about the transport connection on which a message
/// was received. Provided by the listener layer to the handler.
pub struct MessageContext {
    /// The client's source address (IP + port).
    pub client_addr: SocketAddr,
    /// The server address the message was received on.
    pub server_addr: SocketAddr,
    /// The transport protocol (UDP or TCP).
    pub protocol: TransportProtocol,
    /// The server's public IP (for XOR-RELAYED-ADDRESS).
    pub server_public_ip: IpAddr,
}

// ---------------------------------------------------------------------------
// HandleResult — what the listener should do after handling a message
// ---------------------------------------------------------------------------

/// The result of processing a STUN/TURN message.
///
/// The listener layer inspects these actions and performs the actual I/O.
pub enum HandleResult {
    /// Send this response back to the client.
    Response(Vec<u8>),
    /// Relay data to a peer via the allocation's relay socket.
    RelayToPeer {
        peer_addr: SocketAddr,
        data: Vec<u8>,
        relay_socket: Arc<UdpSocket>,
    },
    /// Send ChannelData to a peer via the relay socket.
    ChannelDataToPeer {
        peer_addr: SocketAddr,
        data: Vec<u8>,
        relay_socket: Arc<UdpSocket>,
    },
    /// A new allocation was created. The listener should send the response
    /// to the client AND spawn a relay receiver task for the relay socket.
    AllocationCreated {
        /// The encoded STUN success response to send back to the client.
        response: Vec<u8>,
        /// The relay socket for the new allocation (used to receive peer data).
        relay_socket: Arc<UdpSocket>,
        /// The relay address (public IP + allocated port).
        relay_addr: SocketAddr,
        /// The 5-tuple identifying this allocation's client connection.
        five_tuple: FiveTuple,
    },
    /// No response needed (e.g., invalid message silently dropped).
    None,
}

// ---------------------------------------------------------------------------
// TurnHandler — the core message handler
// ---------------------------------------------------------------------------

/// Processes incoming STUN/TURN messages and returns I/O actions.
///
/// All state is accessed through `Arc`-wrapped shared references, making
/// the handler safe to share across tasks.
pub struct TurnHandler {
    /// Shared allocation state.
    allocations: Arc<AllocationManager>,
    /// Port pool for allocating relay ports.
    port_pool: Arc<tokio::sync::Mutex<PortPool>>,
    /// Shared secret for time-limited credentials.
    shared_secret: Vec<u8>,
    /// Authentication realm (e.g., "duskchat.app").
    realm: String,
    /// Secret used for HMAC-based nonce generation.
    nonce_secret: Vec<u8>,
    /// The server's public IP address for relay addresses.
    server_public_ip: IpAddr,
    /// Software name for the SOFTWARE attribute.
    software: String,
}

impl TurnHandler {
    /// Create a new TURN message handler.
    pub fn new(
        allocations: Arc<AllocationManager>,
        port_pool: Arc<tokio::sync::Mutex<PortPool>>,
        shared_secret: Vec<u8>,
        realm: String,
        nonce_secret: Vec<u8>,
        server_public_ip: IpAddr,
    ) -> Self {
        Self {
            allocations,
            port_pool,
            shared_secret,
            realm,
            nonce_secret,
            server_public_ip,
            software: SOFTWARE_NAME.to_string(),
        }
    }

    /// Handle an incoming STUN message.
    ///
    /// Dispatches to the appropriate method handler based on the message
    /// type. Returns a list of actions for the listener to execute.
    pub async fn handle_message(
        &self,
        msg: &StunMessage,
        ctx: &MessageContext,
    ) -> Vec<HandleResult> {
        let result = match (msg.msg_type.method, msg.msg_type.class) {
            (Method::Binding, Class::Request) => {
                self.handle_binding_request(msg, ctx).await
            }
            (Method::Allocate, Class::Request) => {
                self.handle_allocate_request(msg, ctx).await
            }
            (Method::Refresh, Class::Request) => {
                self.handle_refresh_request(msg, ctx).await
            }
            (Method::CreatePermission, Class::Request) => {
                self.handle_create_permission_request(msg, ctx).await
            }
            (Method::ChannelBind, Class::Request) => {
                self.handle_channel_bind_request(msg, ctx).await
            }
            (Method::Send, Class::Indication) => {
                self.handle_send_indication(msg, ctx).await
            }
            _ => {
                log::debug!(
                    "ignoring unsupported message: {:?} {:?}",
                    msg.msg_type.method,
                    msg.msg_type.class
                );
                HandleResult::None
            }
        };

        vec![result]
    }

    /// Handle incoming ChannelData (compact framing for channel bindings).
    pub async fn handle_channel_data(
        &self,
        channel_data: &ChannelData,
        ctx: &MessageContext,
    ) -> Option<HandleResult> {
        let five_tuple = FiveTuple {
            client_addr: ctx.client_addr,
            server_addr: ctx.server_addr,
            protocol: ctx.protocol,
        };

        // Look up the channel binding
        let peer_addr = self
            .allocations
            .get_channel_binding(&five_tuple, channel_data.channel_number)
            .await?;

        // Get the allocation's relay socket
        let alloc_info = self.allocations.get_allocation(&five_tuple).await?;

        Some(HandleResult::ChannelDataToPeer {
            peer_addr,
            data: channel_data.data.clone(),
            relay_socket: alloc_info.relay_socket,
        })
    }

    // -----------------------------------------------------------------------
    // Binding Request (STUN, RFC 5389 §10.1)
    // -----------------------------------------------------------------------

    /// Handle a STUN Binding Request.
    ///
    /// Returns XOR-MAPPED-ADDRESS containing the client's reflexive address.
    /// No authentication required.
    async fn handle_binding_request(
        &self,
        msg: &StunMessage,
        ctx: &MessageContext,
    ) -> HandleResult {
        let mut response = StunMessage::new(
            MessageType::new(Method::Binding, Class::SuccessResponse),
            msg.transaction_id,
        );

        response.add_attribute(StunAttribute::XorMappedAddress(ctx.client_addr));
        response.add_attribute(StunAttribute::Software(self.software.clone()));

        // Binding responses don't require MESSAGE-INTEGRITY (no auth)
        // Add FINGERPRINT for demultiplexing
        let encoded = response.encode_for_fingerprint();
        let fingerprint = compute_fingerprint(&encoded);
        response.add_attribute(StunAttribute::Fingerprint(fingerprint));

        HandleResult::Response(response.encode())
    }

    // -----------------------------------------------------------------------
    // Allocate Request (RFC 5766 §6)
    // -----------------------------------------------------------------------

    /// Handle a TURN Allocate Request per RFC 5766 §6.
    ///
    /// 1. Check no existing allocation for this 5-tuple
    /// 2. Authenticate (challenge if needed)
    /// 3. Validate REQUESTED-TRANSPORT (must be UDP/17)
    /// 4. Check quotas
    /// 5. Allocate port, bind socket
    /// 6. Create allocation
    /// 7. Return success with relay address and lifetime
    async fn handle_allocate_request(
        &self,
        msg: &StunMessage,
        ctx: &MessageContext,
    ) -> HandleResult {
        let five_tuple = FiveTuple {
            client_addr: ctx.client_addr,
            server_addr: ctx.server_addr,
            protocol: ctx.protocol,
        };

        // §6.2 step 1: Check if allocation already exists
        if self.allocations.get_allocation(&five_tuple).await.is_some() {
            return self.build_error_response(msg, 437, "Allocation Mismatch");
        }

        // §6.2 step 2: Authenticate
        let (username, key) = match self.authenticate_request(msg) {
            Ok(creds) => creds,
            Err(error_response) => return HandleResult::Response(error_response),
        };

        // §6.2 step 3: Check REQUESTED-TRANSPORT
        let mut has_requested_transport = false;
        for attr in &msg.attributes {
            if let StunAttribute::RequestedTransport(proto) = attr {
                if *proto != 17 {
                    // Only UDP relay is supported
                    return self.build_error_response(
                        msg,
                        442,
                        "Unsupported Transport Protocol",
                    );
                }
                has_requested_transport = true;
                break;
            }
        }

        if !has_requested_transport {
            return self.build_error_response(msg, 400, "Missing REQUESTED-TRANSPORT");
        }

        // Extract requested lifetime (or use default)
        let requested_lifetime = msg
            .attributes
            .iter()
            .find_map(|a| {
                if let StunAttribute::Lifetime(secs) = a {
                    Some(Duration::from_secs(*secs as u64))
                } else {
                    None
                }
            })
            .unwrap_or(self.allocations.config().default_lifetime);

        // §6.2 step 4: Allocate a port from the pool
        let port = {
            let mut pool = self.port_pool.lock().await;
            match pool.allocate() {
                Some(p) => p,
                None => {
                    return self.build_error_response(msg, 508, "Insufficient Capacity");
                }
            }
        };

        // §6.2 step 5: Bind a UDP socket on the relay port
        let bind_addr = format!("0.0.0.0:{}", port);
        let relay_socket = match UdpSocket::bind(&bind_addr).await {
            Ok(sock) => Arc::new(sock),
            Err(e) => {
                log::error!("failed to bind relay socket on port {}: {}", port, e);
                // Return port to pool
                let mut pool = self.port_pool.lock().await;
                pool.release(port);
                return self.build_error_response(msg, 508, "Insufficient Capacity");
            }
        };

        // The relay address uses the server's public IP
        let relay_addr = SocketAddr::new(ctx.server_public_ip, port);

        // Generate nonce for this allocation
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let nonce = compute_nonce(now_secs, &self.nonce_secret);

        // §6.2 step 6: Create the allocation
        let actual_lifetime = requested_lifetime.min(self.allocations.config().max_lifetime);
        let relay_socket_clone = Arc::clone(&relay_socket);
        let five_tuple_clone = five_tuple.clone();
        match self
            .allocations
            .create_allocation(
                five_tuple,
                username.clone(),
                self.realm.clone(),
                nonce,
                actual_lifetime,
                relay_socket,
                port,
                relay_addr,
            )
            .await
        {
            Ok(_) => {
                log::info!(
                    "created allocation for {} → {} (port {}, lifetime {}s)",
                    ctx.client_addr,
                    relay_addr,
                    port,
                    actual_lifetime.as_secs(),
                );
            }
            Err(e) => {
                // Return port to pool on failure
                let mut pool = self.port_pool.lock().await;
                pool.release(port);
                let (code, reason) = e.to_error_code();
                return self.build_error_response(msg, code, reason);
            }
        }

        // §6.2 step 7: Build success response
        let attrs = vec![
            StunAttribute::XorRelayedAddress(relay_addr),
            StunAttribute::Lifetime(actual_lifetime.as_secs() as u32),
            StunAttribute::XorMappedAddress(ctx.client_addr),
            StunAttribute::Software(self.software.clone()),
        ];

        HandleResult::AllocationCreated {
            response: self.build_success_response(msg, attrs, &key),
            relay_socket: relay_socket_clone,
            relay_addr,
            five_tuple: five_tuple_clone,
        }
    }

    // -----------------------------------------------------------------------
    // Refresh Request (RFC 5766 §7)
    // -----------------------------------------------------------------------

    /// Handle a TURN Refresh Request per RFC 5766 §7.
    ///
    /// 1. Find existing allocation
    /// 2. Authenticate
    /// 3. If LIFETIME=0, delete allocation
    /// 4. Otherwise refresh lifetime (clamped to max)
    async fn handle_refresh_request(
        &self,
        msg: &StunMessage,
        ctx: &MessageContext,
    ) -> HandleResult {
        let five_tuple = FiveTuple {
            client_addr: ctx.client_addr,
            server_addr: ctx.server_addr,
            protocol: ctx.protocol,
        };

        // Check allocation exists
        if self.allocations.get_allocation(&five_tuple).await.is_none() {
            return self.build_error_response(msg, 437, "Allocation Mismatch");
        }

        // Authenticate
        let (_username, key) = match self.authenticate_request(msg) {
            Ok(creds) => creds,
            Err(error_response) => return HandleResult::Response(error_response),
        };

        // Extract requested lifetime (default to config default)
        let requested_lifetime = msg
            .attributes
            .iter()
            .find_map(|a| {
                if let StunAttribute::Lifetime(secs) = a {
                    Some(Duration::from_secs(*secs as u64))
                } else {
                    None
                }
            })
            .unwrap_or(self.allocations.config().default_lifetime);

        // Refresh (or delete if lifetime=0)
        match self
            .allocations
            .refresh_allocation(&five_tuple, requested_lifetime)
            .await
        {
            Ok(actual_lifetime) => {
                if actual_lifetime.is_zero() {
                    // Allocation was deleted — return port to pool
                    if let Some(port) = self.allocations.delete_allocation(&five_tuple).await {
                        let mut pool = self.port_pool.lock().await;
                        pool.release(port);
                    }
                    log::info!("deleted allocation for {} (lifetime=0 refresh)", ctx.client_addr);
                } else {
                    log::debug!(
                        "refreshed allocation for {} (lifetime={}s)",
                        ctx.client_addr,
                        actual_lifetime.as_secs()
                    );
                }

                let attrs = vec![
                    StunAttribute::Lifetime(actual_lifetime.as_secs() as u32),
                    StunAttribute::Software(self.software.clone()),
                ];

                HandleResult::Response(self.build_success_response(msg, attrs, &key))
            }
            Err(e) => {
                let (code, reason) = e.to_error_code();
                self.build_error_response(msg, code, reason)
            }
        }
    }

    // -----------------------------------------------------------------------
    // CreatePermission Request (RFC 5766 §9)
    // -----------------------------------------------------------------------

    /// Handle a TURN CreatePermission Request per RFC 5766 §9.
    ///
    /// 1. Find existing allocation
    /// 2. Authenticate
    /// 3. Extract XOR-PEER-ADDRESS attributes (can have multiple)
    /// 4. Install/refresh permissions for each peer IP
    /// 5. Return empty success
    async fn handle_create_permission_request(
        &self,
        msg: &StunMessage,
        ctx: &MessageContext,
    ) -> HandleResult {
        let five_tuple = FiveTuple {
            client_addr: ctx.client_addr,
            server_addr: ctx.server_addr,
            protocol: ctx.protocol,
        };

        // Check allocation exists
        if self.allocations.get_allocation(&five_tuple).await.is_none() {
            return self.build_error_response(msg, 437, "Allocation Mismatch");
        }

        // Authenticate
        let (_username, key) = match self.authenticate_request(msg) {
            Ok(creds) => creds,
            Err(error_response) => return HandleResult::Response(error_response),
        };

        // Extract all XOR-PEER-ADDRESS attributes
        let peer_ips: Vec<IpAddr> = msg
            .attributes
            .iter()
            .filter_map(|a| {
                if let StunAttribute::XorPeerAddress(addr) = a {
                    Some(addr.ip())
                } else {
                    None
                }
            })
            .collect();

        if peer_ips.is_empty() {
            return self.build_error_response(msg, 400, "Missing XOR-PEER-ADDRESS");
        }

        // Install permissions
        match self
            .allocations
            .create_permission(&five_tuple, peer_ips)
            .await
        {
            Ok(()) => {
                let attrs = vec![
                    StunAttribute::Software(self.software.clone()),
                ];

                HandleResult::Response(self.build_success_response(msg, attrs, &key))
            }
            Err(e) => {
                let (code, reason) = e.to_error_code();
                self.build_error_response(msg, code, reason)
            }
        }
    }

    // -----------------------------------------------------------------------
    // ChannelBind Request (RFC 5766 §11)
    // -----------------------------------------------------------------------

    /// Handle a TURN ChannelBind Request per RFC 5766 §11.
    ///
    /// 1. Find existing allocation
    /// 2. Authenticate
    /// 3. Validate channel number (0x4000-0x7FFE)
    /// 4. Check for conflicting bindings
    /// 5. Bind channel and install permission
    /// 6. Return empty success
    async fn handle_channel_bind_request(
        &self,
        msg: &StunMessage,
        ctx: &MessageContext,
    ) -> HandleResult {
        let five_tuple = FiveTuple {
            client_addr: ctx.client_addr,
            server_addr: ctx.server_addr,
            protocol: ctx.protocol,
        };

        // Check allocation exists
        if self.allocations.get_allocation(&five_tuple).await.is_none() {
            return self.build_error_response(msg, 437, "Allocation Mismatch");
        }

        // Authenticate
        let (_username, key) = match self.authenticate_request(msg) {
            Ok(creds) => creds,
            Err(error_response) => return HandleResult::Response(error_response),
        };

        // Extract CHANNEL-NUMBER
        let channel_number = match msg.attributes.iter().find_map(|a| {
            if let StunAttribute::ChannelNumber(num) = a {
                Some(*num)
            } else {
                None
            }
        }) {
            Some(n) => n,
            None => {
                return self.build_error_response(msg, 400, "Missing CHANNEL-NUMBER");
            }
        };

        // Validate range
        if !(0x4000..=0x7FFE).contains(&channel_number) {
            return self.build_error_response(msg, 400, "Invalid channel number");
        }

        // Extract XOR-PEER-ADDRESS
        let peer_addr = match msg.attributes.iter().find_map(|a| {
            if let StunAttribute::XorPeerAddress(addr) = a {
                Some(*addr)
            } else {
                None
            }
        }) {
            Some(addr) => addr,
            None => {
                return self.build_error_response(msg, 400, "Missing XOR-PEER-ADDRESS");
            }
        };

        // Bind the channel (also installs permission)
        match self
            .allocations
            .bind_channel(&five_tuple, channel_number, peer_addr)
            .await
        {
            Ok(()) => {
                log::debug!(
                    "bound channel 0x{:04x} to {} for {}",
                    channel_number,
                    peer_addr,
                    ctx.client_addr
                );

                let attrs = vec![
                    StunAttribute::Software(self.software.clone()),
                ];

                HandleResult::Response(self.build_success_response(msg, attrs, &key))
            }
            Err(e) => {
                let (code, reason) = e.to_error_code();
                self.build_error_response(msg, code, reason)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Send Indication (RFC 5766 §10)
    // -----------------------------------------------------------------------

    /// Handle a TURN Send Indication per RFC 5766 §10.
    ///
    /// 1. Find existing allocation
    /// 2. Extract XOR-PEER-ADDRESS and DATA attributes
    /// 3. Check permission exists for peer IP
    /// 4. Return RelayToPeer action
    ///
    /// Indications do not generate responses (fire-and-forget).
    async fn handle_send_indication(
        &self,
        msg: &StunMessage,
        ctx: &MessageContext,
    ) -> HandleResult {
        let five_tuple = FiveTuple {
            client_addr: ctx.client_addr,
            server_addr: ctx.server_addr,
            protocol: ctx.protocol,
        };

        // Get the allocation
        let alloc_info = match self.allocations.get_allocation(&five_tuple).await {
            Some(info) => info,
            None => {
                log::debug!("send indication for non-existent allocation from {}", ctx.client_addr);
                return HandleResult::None;
            }
        };

        // Extract XOR-PEER-ADDRESS
        let peer_addr = match msg.attributes.iter().find_map(|a| {
            if let StunAttribute::XorPeerAddress(addr) = a {
                Some(*addr)
            } else {
                None
            }
        }) {
            Some(addr) => addr,
            None => {
                log::debug!("send indication missing XOR-PEER-ADDRESS from {}", ctx.client_addr);
                return HandleResult::None;
            }
        };

        // Extract DATA
        let data = match msg.attributes.iter().find_map(|a| {
            if let StunAttribute::Data(d) = a {
                Some(d.clone())
            } else {
                None
            }
        }) {
            Some(d) => d,
            None => {
                log::debug!("send indication missing DATA from {}", ctx.client_addr);
                return HandleResult::None;
            }
        };

        // Check permission
        if !self
            .allocations
            .has_permission(&five_tuple, &peer_addr.ip())
            .await
        {
            log::debug!(
                "send indication from {} to {} denied: no permission",
                ctx.client_addr,
                peer_addr
            );
            return HandleResult::None;
        }

        HandleResult::RelayToPeer {
            peer_addr,
            data,
            relay_socket: alloc_info.relay_socket,
        }
    }

    // -----------------------------------------------------------------------
    // Authentication (RFC 5389 §10.2.2, long-term credentials)
    // -----------------------------------------------------------------------

    /// Authenticate a STUN request using long-term credentials.
    ///
    /// Returns `Ok((username, key))` on success, or `Err(encoded_error_bytes)`
    /// on failure. The error bytes are a complete STUN error response ready
    /// to send.
    ///
    /// Authentication flow:
    /// 1. No MESSAGE-INTEGRITY → 401 challenge with REALM + NONCE
    /// 2. Stale NONCE → 438 with fresh NONCE
    /// 3. Compute key and validate HMAC
    /// 4. Invalid → 401
    fn authenticate_request(
        &self,
        msg: &StunMessage,
    ) -> Result<(String, Vec<u8>), Vec<u8>> {
        // Step 1: Check for MESSAGE-INTEGRITY
        let message_integrity = match msg.get_message_integrity() {
            Some(mi) => mi,
            None => {
                // No auth at all — send challenge
                return Err(self.build_challenge_response(msg));
            }
        };

        // Get USERNAME, REALM, NONCE
        let username = match msg.get_username() {
            Some(u) => u.to_string(),
            None => {
                return Err(self.encode_error_response(msg, 400, "Missing USERNAME"));
            }
        };

        let _realm = match msg.get_realm() {
            Some(r) => r.to_string(),
            None => {
                return Err(self.encode_error_response(msg, 400, "Missing REALM"));
            }
        };

        let nonce = match msg.get_nonce() {
            Some(n) => n.to_string(),
            None => {
                return Err(self.encode_error_response(msg, 400, "Missing NONCE"));
            }
        };

        // Step 2: Validate nonce (check for staleness)
        if validate_nonce(&nonce, &self.nonce_secret, NONCE_MAX_AGE_SECS).is_err() {
            // Stale nonce — respond with 438 and a fresh nonce
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let fresh_nonce = compute_nonce(now_secs, &self.nonce_secret);

            let mut response = StunMessage::new(
                MessageType::new(msg.msg_type.method, Class::ErrorResponse),
                msg.transaction_id,
            );
            response.add_attribute(StunAttribute::ErrorCode {
                code: 438,
                reason: "Stale Nonce".to_string(),
            });
            response.add_attribute(StunAttribute::Realm(self.realm.clone()));
            response.add_attribute(StunAttribute::Nonce(fresh_nonce));
            response.add_attribute(StunAttribute::Software(self.software.clone()));

            return Err(response.encode());
        }

        // Step 3: Compute the long-term credential key
        // Password = Base64(HMAC-SHA1(shared_secret, username))
        let password_hmac = hmac_sha1(&self.shared_secret, username.as_bytes());
        let password = base64_encode_simple(&password_hmac);
        let key = compute_long_term_key(&username, &self.realm, &password);

        // Step 4: Validate MESSAGE-INTEGRITY
        let integrity_bytes = msg.encode_for_integrity();
        if !validate_message_integrity(message_integrity, &key, &integrity_bytes) {
            return Err(self.encode_error_response(msg, 401, "Unauthorized"));
        }

        Ok((username, key.to_vec()))
    }

    // -----------------------------------------------------------------------
    // Response building helpers
    // -----------------------------------------------------------------------

    /// Build an error response and return it as a [`HandleResult::Response`].
    fn build_error_response(
        &self,
        msg: &StunMessage,
        code: u16,
        reason: &str,
    ) -> HandleResult {
        HandleResult::Response(self.encode_error_response(msg, code, reason))
    }

    /// Encode a STUN error response as wire-format bytes.
    ///
    /// Error responses include ERROR-CODE, SOFTWARE, and FINGERPRINT
    /// but not MESSAGE-INTEGRITY (since the client may not have credentials yet).
    fn encode_error_response(
        &self,
        msg: &StunMessage,
        code: u16,
        reason: &str,
    ) -> Vec<u8> {
        let mut response = StunMessage::new(
            MessageType::new(msg.msg_type.method, Class::ErrorResponse),
            msg.transaction_id,
        );

        response.add_attribute(StunAttribute::ErrorCode {
            code,
            reason: reason.to_string(),
        });
        response.add_attribute(StunAttribute::Software(self.software.clone()));

        // Add FINGERPRINT
        let fp_bytes = response.encode_for_fingerprint();
        let fingerprint = compute_fingerprint(&fp_bytes);
        response.add_attribute(StunAttribute::Fingerprint(fingerprint));

        response.encode()
    }

    /// Build a STUN success response with MESSAGE-INTEGRITY and FINGERPRINT.
    ///
    /// The `key` is the long-term credential key used for MESSAGE-INTEGRITY.
    fn build_success_response(
        &self,
        msg: &StunMessage,
        attrs: Vec<StunAttribute>,
        key: &[u8],
    ) -> Vec<u8> {
        let mut response = StunMessage::new(
            MessageType::new(msg.msg_type.method, Class::SuccessResponse),
            msg.transaction_id,
        );

        for attr in attrs {
            response.add_attribute(attr);
        }

        // Compute MESSAGE-INTEGRITY over the message with adjusted length
        let integrity_bytes = response.encode_for_integrity();
        let hmac = compute_message_integrity(key, &integrity_bytes);
        response.add_attribute(StunAttribute::MessageIntegrity(hmac));

        // Compute FINGERPRINT over the message including MESSAGE-INTEGRITY
        let fp_bytes = response.encode_for_fingerprint();
        let fingerprint = compute_fingerprint(&fp_bytes);
        response.add_attribute(StunAttribute::Fingerprint(fingerprint));

        response.encode()
    }

    /// Build a 401 challenge response with REALM and NONCE.
    ///
    /// This is sent when a client sends a request without credentials,
    /// prompting them to retry with authentication.
    fn build_challenge_response(&self, msg: &StunMessage) -> Vec<u8> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let nonce = compute_nonce(now_secs, &self.nonce_secret);

        let mut response = StunMessage::new(
            MessageType::new(msg.msg_type.method, Class::ErrorResponse),
            msg.transaction_id,
        );

        response.add_attribute(StunAttribute::ErrorCode {
            code: 401,
            reason: "Unauthorized".to_string(),
        });
        response.add_attribute(StunAttribute::Realm(self.realm.clone()));
        response.add_attribute(StunAttribute::Nonce(nonce));
        response.add_attribute(StunAttribute::Software(self.software.clone()));

        // Add FINGERPRINT (no MESSAGE-INTEGRITY on challenge responses)
        let fp_bytes = response.encode_for_fingerprint();
        let fingerprint = compute_fingerprint(&fp_bytes);
        response.add_attribute(StunAttribute::Fingerprint(fingerprint));

        response.encode()
    }
}

// ---------------------------------------------------------------------------
// Base64 helper (simple encode only, for password generation)
// ---------------------------------------------------------------------------

/// Simple Base64 encoding using standard alphabet with padding.
///
/// This duplicates the private function in credentials.rs to avoid
/// exposing it as a public API. In a future refactor, the base64
/// utilities should be extracted to a shared utility module.
fn base64_encode_simple(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    let chunks = data.chunks(3);

    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::turn::allocation::{AllocationConfig, AllocationManager};
    use crate::turn::port_pool::PortPool;
    use crate::turn::stun::{Class, MessageType, Method};
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_handler() -> TurnHandler {
        let config = AllocationConfig {
            max_allocations: 100,
            max_per_user: 10,
            realm: "test.example.com".to_string(),
            ..Default::default()
        };
        let allocations = Arc::new(AllocationManager::new(config));
        let port_pool = Arc::new(tokio::sync::Mutex::new(PortPool::new(50000, 50100)));

        TurnHandler::new(
            allocations,
            port_pool,
            b"test_shared_secret".to_vec(),
            "test.example.com".to_string(),
            b"test_nonce_secret".to_vec(),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        )
    }

    fn test_ctx() -> MessageContext {
        MessageContext {
            client_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345)),
            server_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 3478)),
            protocol: TransportProtocol::Udp,
            server_public_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        }
    }

    #[tokio::test]
    async fn test_binding_request() {
        let handler = test_handler();
        let ctx = test_ctx();

        let msg = StunMessage::new(
            MessageType::new(Method::Binding, Class::Request),
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        );

        let results = handler.handle_message(&msg, &ctx).await;
        assert_eq!(results.len(), 1);

        match &results[0] {
            HandleResult::Response(bytes) => {
                let response = StunMessage::decode(bytes).unwrap();
                assert_eq!(response.msg_type.method, Method::Binding);
                assert_eq!(response.msg_type.class, Class::SuccessResponse);
                assert_eq!(response.transaction_id, msg.transaction_id);

                // Should contain XOR-MAPPED-ADDRESS
                let has_xor_mapped = response.attributes.iter().any(|a| {
                    matches!(a, StunAttribute::XorMappedAddress(_))
                });
                assert!(has_xor_mapped, "response should contain XOR-MAPPED-ADDRESS");
            }
            _ => panic!("expected Response"),
        }
    }

    #[tokio::test]
    async fn test_allocate_request_challenge() {
        let handler = test_handler();
        let ctx = test_ctx();

        // Send Allocate without credentials → should get 401 challenge
        let mut msg = StunMessage::new(
            MessageType::new(Method::Allocate, Class::Request),
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        );
        msg.add_attribute(StunAttribute::RequestedTransport(17));

        let results = handler.handle_message(&msg, &ctx).await;
        assert_eq!(results.len(), 1);

        match &results[0] {
            HandleResult::Response(bytes) => {
                let response = StunMessage::decode(bytes).unwrap();
                assert_eq!(response.msg_type.method, Method::Allocate);
                assert_eq!(response.msg_type.class, Class::ErrorResponse);

                // Should have 401 error code
                let error = response.attributes.iter().find_map(|a| {
                    if let StunAttribute::ErrorCode { code, .. } = a {
                        Some(*code)
                    } else {
                        None
                    }
                });
                assert_eq!(error, Some(401));

                // Should have REALM and NONCE for challenge
                assert!(response.get_realm().is_some(), "challenge should include REALM");
                assert!(response.get_nonce().is_some(), "challenge should include NONCE");
            }
            _ => panic!("expected Response"),
        }
    }

    #[tokio::test]
    async fn test_allocate_missing_transport() {
        let handler = test_handler();
        let ctx = test_ctx();

        // Allocate without REQUESTED-TRANSPORT and with (fake) auth
        // The handler should challenge first since there's no MESSAGE-INTEGRITY
        let msg = StunMessage::new(
            MessageType::new(Method::Allocate, Class::Request),
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        );

        let results = handler.handle_message(&msg, &ctx).await;
        assert_eq!(results.len(), 1);

        // Without auth, should get 401 challenge first
        match &results[0] {
            HandleResult::Response(bytes) => {
                let response = StunMessage::decode(bytes).unwrap();
                assert_eq!(response.msg_type.class, Class::ErrorResponse);
            }
            _ => panic!("expected Response"),
        }
    }

    #[tokio::test]
    async fn test_send_indication_no_allocation() {
        let handler = test_handler();
        let ctx = test_ctx();

        let mut msg = StunMessage::new(
            MessageType::new(Method::Send, Class::Indication),
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        );
        msg.add_attribute(StunAttribute::XorPeerAddress(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 9999)),
        ));
        msg.add_attribute(StunAttribute::Data(vec![1, 2, 3]));

        let results = handler.handle_message(&msg, &ctx).await;
        assert_eq!(results.len(), 1);

        // No allocation → should return None (indications don't get error responses)
        assert!(matches!(results[0], HandleResult::None));
    }

    #[tokio::test]
    async fn test_channel_data_no_binding() {
        let handler = test_handler();
        let ctx = test_ctx();

        let channel_data = ChannelData {
            channel_number: 0x4000,
            data: vec![1, 2, 3, 4],
        };

        let result = handler.handle_channel_data(&channel_data, &ctx).await;
        assert!(result.is_none());
    }

    #[test]
    fn test_base64_encode_simple_matches() {
        assert_eq!(base64_encode_simple(b""), "");
        assert_eq!(base64_encode_simple(b"f"), "Zg==");
        assert_eq!(base64_encode_simple(b"fo"), "Zm8=");
        assert_eq!(base64_encode_simple(b"foo"), "Zm9v");
        assert_eq!(base64_encode_simple(b"foobar"), "Zm9vYmFy");
    }
}
