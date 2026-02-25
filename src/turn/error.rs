// TURN server error types
//
// Covers all error conditions that can arise during STUN/TURN message
// processing, credential validation, and allocation management.

use std::fmt;

/// Comprehensive error type for TURN server operations.
///
/// Each variant maps to a specific failure condition in the STUN/TURN
/// protocol stack, from low-level parse errors to high-level allocation
/// policy violations.
#[derive(Debug, Clone)]
pub enum TurnError {
    /// Invalid STUN message format: bad header, truncated message,
    /// missing magic cookie, or malformed TLV attributes.
    StunParseError(String),

    /// MESSAGE-INTEGRITY attribute does not match the computed HMAC-SHA1.
    /// This means either the password is wrong or the message was tampered with.
    InvalidMessageIntegrity,

    /// The NONCE has expired. The client should retry with a fresh nonce
    /// from the 438 Stale Nonce error response.
    StaleNonce,

    /// The client already has an allocation on this 5-tuple, or is
    /// attempting an operation that conflicts with existing allocation state
    /// (RFC 5766 §6.2).
    AllocationMismatch,

    /// The server has reached its per-user or global allocation quota.
    /// Maps to TURN error code 486.
    AllocationQuotaReached,

    /// The server cannot fulfill the request due to resource constraints
    /// (e.g., no relay ports available). Maps to TURN error code 508.
    InsufficientCapacity,

    /// The request lacks valid credentials, or the credentials have expired.
    /// Maps to STUN error code 401.
    Unauthorized,

    /// The peer address in the request is forbidden by server policy
    /// (e.g., loopback or private IP filtering). Maps to TURN error code 403.
    ForbiddenIp,

    /// The REQUESTED-TRANSPORT attribute specifies a transport protocol
    /// that the server does not support (e.g., TCP relay when only UDP
    /// is available). Maps to TURN error code 442.
    UnsupportedTransport,

    /// An I/O error occurred on a socket or file operation.
    IoError(String),
}

impl fmt::Display for TurnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TurnError::StunParseError(msg) => write!(f, "STUN parse error: {}", msg),
            TurnError::InvalidMessageIntegrity => write!(f, "invalid MESSAGE-INTEGRITY"),
            TurnError::StaleNonce => write!(f, "stale nonce"),
            TurnError::AllocationMismatch => write!(f, "allocation mismatch"),
            TurnError::AllocationQuotaReached => write!(f, "allocation quota reached"),
            TurnError::InsufficientCapacity => write!(f, "insufficient capacity"),
            TurnError::Unauthorized => write!(f, "unauthorized"),
            TurnError::ForbiddenIp => write!(f, "forbidden IP address"),
            TurnError::UnsupportedTransport => write!(f, "unsupported transport protocol"),
            TurnError::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for TurnError {}

impl From<std::io::Error> for TurnError {
    fn from(err: std::io::Error) -> Self {
        TurnError::IoError(err.to_string())
    }
}

/// Maps a [`TurnError`] to the corresponding STUN/TURN error code
/// for use in error response messages.
///
/// Error codes follow RFC 5389 §15.6 and RFC 5766 §6.
impl TurnError {
    /// Returns the STUN/TURN error code and default reason phrase for this error.
    pub fn to_error_code(&self) -> (u16, &'static str) {
        match self {
            TurnError::StunParseError(_) => (400, "Bad Request"),
            TurnError::InvalidMessageIntegrity => (401, "Unauthorized"),
            TurnError::StaleNonce => (438, "Stale Nonce"),
            TurnError::AllocationMismatch => (437, "Allocation Mismatch"),
            TurnError::AllocationQuotaReached => (486, "Allocation Quota Reached"),
            TurnError::InsufficientCapacity => (508, "Insufficient Capacity"),
            TurnError::Unauthorized => (401, "Unauthorized"),
            TurnError::ForbiddenIp => (403, "Forbidden"),
            TurnError::UnsupportedTransport => (442, "Unsupported Transport Protocol"),
            TurnError::IoError(_) => (500, "Server Error"),
        }
    }
}
