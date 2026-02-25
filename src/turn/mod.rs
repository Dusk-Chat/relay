// TURN server module for Dusk relay
//
// Implements RFC 5389 (STUN) and RFC 5766 (TURN) protocol types,
// message parsing/serialization, credential management, port allocation,
// and the full server with UDP/TCP listeners.
//
// This module is organized as follows:
// - stun: STUN message format, parsing, serialization
// - attributes: STUN/TURN attribute types and encoding
// - credentials: HMAC-SHA1 time-limited credential generation/validation
// - allocation: TURN allocation state machine
// - port_pool: Relay port allocation pool
// - handler: TURN message handler (request dispatch + response building)
// - udp_listener: UDP listener task (receives datagrams, spawns relay receivers)
// - tcp_listener: TCP listener task (accepts connections, frames STUN/ChannelData)
// - server: Top-level TURN server orchestration (config, startup, handle)
// - error: Error types

pub mod stun;
pub mod attributes;
pub mod credentials;
pub mod error;
pub mod port_pool;
pub mod allocation;
pub mod handler;
pub mod udp_listener;
pub mod tcp_listener;
pub mod server;

pub use server::{TurnServer, TurnServerConfig, TurnServerHandle};
