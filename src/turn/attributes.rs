// STUN/TURN attribute types and TLV encoding/decoding
//
// Implements attributes per RFC 5389 (STUN) and RFC 5766 (TURN).
// Each attribute is a Type-Length-Value (TLV) structure:
//   Type:   2 bytes (attribute type code)
//   Length: 2 bytes (value length, excluding padding)
//   Value:  variable (padded to 4-byte boundary with zeros)
//
// XOR-encoded address attributes (XOR-MAPPED-ADDRESS, XOR-PEER-ADDRESS,
// XOR-RELAYED-ADDRESS) use the STUN magic cookie and transaction ID
// to XOR the address bytes, preventing NAT ALGs from rewriting them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::turn::error::TurnError;
use crate::turn::stun::MAGIC_COOKIE;

// ---------------------------------------------------------------------------
// Attribute type codes
// ---------------------------------------------------------------------------

/// RFC 5389 STUN attribute type codes
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_SOFTWARE: u16 = 0x8022;
pub const ATTR_FINGERPRINT: u16 = 0x8028;

/// RFC 5766 TURN attribute type codes
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub const ATTR_LIFETIME: u16 = 0x000D;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
pub const ATTR_EVEN_PORT: u16 = 0x0018;
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
pub const ATTR_DONT_FRAGMENT: u16 = 0x001A;

// ---------------------------------------------------------------------------
// Address family constants
// ---------------------------------------------------------------------------

const ADDR_FAMILY_IPV4: u8 = 0x01;
const ADDR_FAMILY_IPV6: u8 = 0x02;

// ---------------------------------------------------------------------------
// StunAttribute enum
// ---------------------------------------------------------------------------

/// A parsed STUN or TURN attribute.
///
/// Each variant corresponds to a specific attribute type. Unknown attributes
/// are preserved as raw bytes for forwarding or diagnostic purposes.
#[derive(Debug, Clone)]
pub enum StunAttribute {
    // ---- RFC 5389 STUN attributes ----

    /// MAPPED-ADDRESS (0x0001): The reflexive transport address of the client
    /// as seen by the server. Uses plain (non-XOR) encoding.
    MappedAddress(SocketAddr),

    /// USERNAME (0x0006): The username for message integrity, encoded as UTF-8.
    Username(String),

    /// MESSAGE-INTEGRITY (0x0008): 20-byte HMAC-SHA1 over the STUN message
    /// (up to but not including this attribute).
    MessageIntegrity([u8; 20]),

    /// ERROR-CODE (0x0009): Error response code and human-readable reason phrase.
    /// Code is in range 300-699 per RFC 5389 §15.6.
    ErrorCode { code: u16, reason: String },

    /// UNKNOWN-ATTRIBUTES (0x000A): List of attribute types that the server
    /// did not understand. Used in 420 Unknown Attribute error responses.
    UnknownAttributes(Vec<u16>),

    /// REALM (0x0014): The authentication realm, encoded as UTF-8.
    /// Used with long-term credential mechanism.
    Realm(String),

    /// NONCE (0x0015): A server-generated nonce for replay protection.
    Nonce(String),

    /// XOR-MAPPED-ADDRESS (0x0020): Same as MAPPED-ADDRESS but XOR-encoded
    /// with the magic cookie (and transaction ID for IPv6) to prevent
    /// NAT ALG interference.
    XorMappedAddress(SocketAddr),

    /// SOFTWARE (0x8022): Textual description of the software being used.
    /// Informational only.
    Software(String),

    /// FINGERPRINT (0x8028): CRC32 of the STUN message XORed with 0x5354554e.
    /// Used to demultiplex STUN from other protocols on the same port.
    Fingerprint(u32),

    // ---- RFC 5766 TURN attributes ----

    /// CHANNEL-NUMBER (0x000C): Channel number for ChannelBind.
    /// Must be in range 0x4000-0x7FFF.
    ChannelNumber(u16),

    /// LIFETIME (0x000D): Requested or granted allocation lifetime in seconds.
    Lifetime(u32),

    /// XOR-PEER-ADDRESS (0x0012): The peer address for Send/Data indications,
    /// CreatePermission, and ChannelBind. XOR-encoded like XOR-MAPPED-ADDRESS.
    XorPeerAddress(SocketAddr),

    /// DATA (0x0013): The application data payload in Send/Data indications.
    Data(Vec<u8>),

    /// XOR-RELAYED-ADDRESS (0x0016): The relayed transport address allocated
    /// by the server. XOR-encoded.
    XorRelayedAddress(SocketAddr),

    /// EVEN-PORT (0x0018): Requests an even port number for the relay address.
    /// The boolean indicates the R bit (reserve next-higher port).
    EvenPort(bool),

    /// REQUESTED-TRANSPORT (0x0019): The transport protocol for the relay.
    /// Value is an IANA protocol number (17 = UDP, 6 = TCP).
    RequestedTransport(u8),

    /// DONT-FRAGMENT (0x001A): Requests that the server set the DF bit
    /// in outgoing UDP packets. No value (zero-length attribute).
    DontFragment,

    /// REQUESTED-ADDRESS-FAMILY (0x0017): Requests a specific address family
    /// for the relayed address (0x01 = IPv4, 0x02 = IPv6).
    RequestedAddressFamily(u8),

    /// Unknown/unsupported attribute preserved as raw bytes.
    Unknown { attr_type: u16, value: Vec<u8> },
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decode a single attribute from its type code and raw value bytes.
///
/// The `transaction_id` is needed for XOR address decoding.
pub fn decode_attribute(
    attr_type: u16,
    value: &[u8],
    transaction_id: &[u8; 12],
) -> Result<StunAttribute, TurnError> {
    match attr_type {
        ATTR_MAPPED_ADDRESS => decode_mapped_address(value),
        ATTR_USERNAME => decode_utf8_string(value).map(StunAttribute::Username),
        ATTR_MESSAGE_INTEGRITY => decode_message_integrity(value),
        ATTR_ERROR_CODE => decode_error_code(value),
        ATTR_UNKNOWN_ATTRIBUTES => decode_unknown_attributes(value),
        ATTR_REALM => decode_utf8_string(value).map(StunAttribute::Realm),
        ATTR_NONCE => decode_utf8_string(value).map(StunAttribute::Nonce),
        ATTR_XOR_MAPPED_ADDRESS => {
            decode_xor_address(value, transaction_id).map(StunAttribute::XorMappedAddress)
        }
        ATTR_SOFTWARE => decode_utf8_string(value).map(StunAttribute::Software),
        ATTR_FINGERPRINT => decode_fingerprint(value),
        ATTR_CHANNEL_NUMBER => decode_channel_number(value),
        ATTR_LIFETIME => decode_lifetime(value),
        ATTR_XOR_PEER_ADDRESS => {
            decode_xor_address(value, transaction_id).map(StunAttribute::XorPeerAddress)
        }
        ATTR_DATA => Ok(StunAttribute::Data(value.to_vec())),
        ATTR_XOR_RELAYED_ADDRESS => {
            decode_xor_address(value, transaction_id).map(StunAttribute::XorRelayedAddress)
        }
        ATTR_REQUESTED_ADDRESS_FAMILY => decode_requested_address_family(value),
        ATTR_EVEN_PORT => decode_even_port(value),
        ATTR_REQUESTED_TRANSPORT => decode_requested_transport(value),
        ATTR_DONT_FRAGMENT => Ok(StunAttribute::DontFragment),
        _ => Ok(StunAttribute::Unknown {
            attr_type,
            value: value.to_vec(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Encode a single attribute into TLV wire format with 4-byte padding.
///
/// Returns the complete TLV bytes: type (2) + length (2) + value + padding.
pub fn encode_attribute(attr: &StunAttribute, transaction_id: &[u8; 12]) -> Vec<u8> {
    let (attr_type, value) = encode_attribute_value(attr, transaction_id);
    let value_len = value.len();
    let padded_len = (value_len + 3) & !3;

    let mut buf = Vec::with_capacity(4 + padded_len);
    buf.extend_from_slice(&attr_type.to_be_bytes());
    buf.extend_from_slice(&(value_len as u16).to_be_bytes());
    buf.extend_from_slice(&value);

    // Pad to 4-byte boundary
    let padding = padded_len - value_len;
    for _ in 0..padding {
        buf.push(0);
    }

    buf
}

/// Encode an attribute's value bytes (without the TLV header or padding).
/// Returns (attribute_type_code, value_bytes).
fn encode_attribute_value(attr: &StunAttribute, transaction_id: &[u8; 12]) -> (u16, Vec<u8>) {
    match attr {
        StunAttribute::MappedAddress(addr) => {
            (ATTR_MAPPED_ADDRESS, encode_plain_address(addr))
        }
        StunAttribute::Username(s) => (ATTR_USERNAME, s.as_bytes().to_vec()),
        StunAttribute::MessageIntegrity(hmac) => (ATTR_MESSAGE_INTEGRITY, hmac.to_vec()),
        StunAttribute::ErrorCode { code, reason } => {
            (ATTR_ERROR_CODE, encode_error_code(*code, reason))
        }
        StunAttribute::UnknownAttributes(types) => {
            let mut buf = Vec::with_capacity(types.len() * 2);
            for &t in types {
                buf.extend_from_slice(&t.to_be_bytes());
            }
            (ATTR_UNKNOWN_ATTRIBUTES, buf)
        }
        StunAttribute::Realm(s) => (ATTR_REALM, s.as_bytes().to_vec()),
        StunAttribute::Nonce(s) => (ATTR_NONCE, s.as_bytes().to_vec()),
        StunAttribute::XorMappedAddress(addr) => {
            (ATTR_XOR_MAPPED_ADDRESS, encode_xor_address(addr, transaction_id))
        }
        StunAttribute::Software(s) => (ATTR_SOFTWARE, s.as_bytes().to_vec()),
        StunAttribute::Fingerprint(val) => (ATTR_FINGERPRINT, val.to_be_bytes().to_vec()),
        StunAttribute::ChannelNumber(num) => {
            // Channel number is 16 bits followed by 16 bits of RFFU (reserved)
            let mut buf = vec![0u8; 4];
            buf[0..2].copy_from_slice(&num.to_be_bytes());
            (ATTR_CHANNEL_NUMBER, buf)
        }
        StunAttribute::Lifetime(secs) => (ATTR_LIFETIME, secs.to_be_bytes().to_vec()),
        StunAttribute::XorPeerAddress(addr) => {
            (ATTR_XOR_PEER_ADDRESS, encode_xor_address(addr, transaction_id))
        }
        StunAttribute::Data(data) => (ATTR_DATA, data.clone()),
        StunAttribute::XorRelayedAddress(addr) => {
            (ATTR_XOR_RELAYED_ADDRESS, encode_xor_address(addr, transaction_id))
        }
        StunAttribute::RequestedAddressFamily(family) => {
            let mut buf = vec![0u8; 4];
            buf[0] = *family;
            (ATTR_REQUESTED_ADDRESS_FAMILY, buf)
        }
        StunAttribute::EvenPort(reserve) => {
            let byte = if *reserve { 0x80 } else { 0x00 };
            (ATTR_EVEN_PORT, vec![byte])
        }
        StunAttribute::RequestedTransport(proto) => {
            // Protocol number in first byte, followed by 3 bytes RFFU
            let mut buf = vec![0u8; 4];
            buf[0] = *proto;
            (ATTR_REQUESTED_TRANSPORT, buf)
        }
        StunAttribute::DontFragment => (ATTR_DONT_FRAGMENT, vec![]),
        StunAttribute::Unknown { attr_type, value } => (*attr_type, value.clone()),
    }
}

// ---------------------------------------------------------------------------
// Address encoding/decoding helpers
// ---------------------------------------------------------------------------

/// Decode a plain (non-XOR) MAPPED-ADDRESS attribute value.
///
/// Format: 1 byte reserved, 1 byte family, 2 bytes port, 4/16 bytes address
fn decode_mapped_address(value: &[u8]) -> Result<StunAttribute, TurnError> {
    if value.len() < 4 {
        return Err(TurnError::StunParseError(
            "MAPPED-ADDRESS too short".into(),
        ));
    }

    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);

    let addr = match family {
        ADDR_FAMILY_IPV4 => {
            if value.len() < 8 {
                return Err(TurnError::StunParseError(
                    "MAPPED-ADDRESS IPv4 too short".into(),
                ));
            }
            let ip = Ipv4Addr::new(value[4], value[5], value[6], value[7]);
            SocketAddr::new(IpAddr::V4(ip), port)
        }
        ADDR_FAMILY_IPV6 => {
            if value.len() < 20 {
                return Err(TurnError::StunParseError(
                    "MAPPED-ADDRESS IPv6 too short".into(),
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            let ip = Ipv6Addr::from(octets);
            SocketAddr::new(IpAddr::V6(ip), port)
        }
        _ => {
            return Err(TurnError::StunParseError(format!(
                "unknown address family: 0x{:02x}",
                family
            )));
        }
    };

    Ok(StunAttribute::MappedAddress(addr))
}

/// Encode a plain (non-XOR) address into wire format.
fn encode_plain_address(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut buf = vec![0u8; 8];
            buf[0] = 0; // reserved
            buf[1] = ADDR_FAMILY_IPV4;
            buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v4.ip().octets());
            buf
        }
        SocketAddr::V6(v6) => {
            let mut buf = vec![0u8; 20];
            buf[0] = 0; // reserved
            buf[1] = ADDR_FAMILY_IPV6;
            buf[2..4].copy_from_slice(&v6.port().to_be_bytes());
            buf[4..20].copy_from_slice(&v6.ip().octets());
            buf
        }
    }
}

/// Decode an XOR-encoded address (XOR-MAPPED-ADDRESS, XOR-PEER-ADDRESS,
/// XOR-RELAYED-ADDRESS) per RFC 5389 §15.2.
///
/// For IPv4: port is XORed with top 16 bits of magic cookie;
///           address is XORed with magic cookie.
/// For IPv6: port is XORed with top 16 bits of magic cookie;
///           address is XORed with magic cookie || transaction ID (16 bytes).
fn decode_xor_address(
    value: &[u8],
    transaction_id: &[u8; 12],
) -> Result<SocketAddr, TurnError> {
    if value.len() < 4 {
        return Err(TurnError::StunParseError(
            "XOR address attribute too short".into(),
        ));
    }

    let family = value[1];
    let x_port = u16::from_be_bytes([value[2], value[3]]);
    let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
    let port = x_port ^ u16::from_be_bytes([cookie_bytes[0], cookie_bytes[1]]);

    match family {
        ADDR_FAMILY_IPV4 => {
            if value.len() < 8 {
                return Err(TurnError::StunParseError(
                    "XOR-MAPPED-ADDRESS IPv4 too short".into(),
                ));
            }
            let x_addr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let addr = x_addr ^ MAGIC_COOKIE;
            let ip = Ipv4Addr::from(addr);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        ADDR_FAMILY_IPV6 => {
            if value.len() < 20 {
                return Err(TurnError::StunParseError(
                    "XOR-MAPPED-ADDRESS IPv6 too short".into(),
                ));
            }
            // Build the 16-byte XOR mask: magic cookie (4 bytes) + transaction ID (12 bytes)
            let mut xor_mask = [0u8; 16];
            xor_mask[0..4].copy_from_slice(&cookie_bytes);
            xor_mask[4..16].copy_from_slice(transaction_id);

            let mut addr_bytes = [0u8; 16];
            for i in 0..16 {
                addr_bytes[i] = value[4 + i] ^ xor_mask[i];
            }
            let ip = Ipv6Addr::from(addr_bytes);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => Err(TurnError::StunParseError(format!(
            "unknown address family in XOR address: 0x{:02x}",
            family
        ))),
    }
}

/// Encode an address using XOR encoding per RFC 5389 §15.2.
fn encode_xor_address(addr: &SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
    let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
    let x_port = addr.port() ^ u16::from_be_bytes([cookie_bytes[0], cookie_bytes[1]]);

    match addr {
        SocketAddr::V4(v4) => {
            let mut buf = vec![0u8; 8];
            buf[0] = 0; // reserved
            buf[1] = ADDR_FAMILY_IPV4;
            buf[2..4].copy_from_slice(&x_port.to_be_bytes());
            let x_addr = u32::from_be_bytes(v4.ip().octets()) ^ MAGIC_COOKIE;
            buf[4..8].copy_from_slice(&x_addr.to_be_bytes());
            buf
        }
        SocketAddr::V6(v6) => {
            let mut buf = vec![0u8; 20];
            buf[0] = 0; // reserved
            buf[1] = ADDR_FAMILY_IPV6;
            buf[2..4].copy_from_slice(&x_port.to_be_bytes());

            // XOR mask: magic cookie (4 bytes) + transaction ID (12 bytes)
            let mut xor_mask = [0u8; 16];
            xor_mask[0..4].copy_from_slice(&cookie_bytes);
            xor_mask[4..16].copy_from_slice(transaction_id);

            let octets = v6.ip().octets();
            for i in 0..16 {
                buf[4 + i] = octets[i] ^ xor_mask[i];
            }
            buf
        }
    }
}

// ---------------------------------------------------------------------------
// Specific attribute decoders
// ---------------------------------------------------------------------------

/// Decode UTF-8 string from raw bytes.
fn decode_utf8_string(value: &[u8]) -> Result<String, TurnError> {
    String::from_utf8(value.to_vec()).map_err(|e| {
        TurnError::StunParseError(format!("invalid UTF-8 in attribute: {}", e))
    })
}

/// Decode MESSAGE-INTEGRITY (exactly 20 bytes HMAC-SHA1).
fn decode_message_integrity(value: &[u8]) -> Result<StunAttribute, TurnError> {
    if value.len() != 20 {
        return Err(TurnError::StunParseError(format!(
            "MESSAGE-INTEGRITY must be 20 bytes, got {}",
            value.len()
        )));
    }
    let mut hmac = [0u8; 20];
    hmac.copy_from_slice(value);
    Ok(StunAttribute::MessageIntegrity(hmac))
}

/// Decode ERROR-CODE attribute per RFC 5389 §15.6.
///
/// Format: 2 bytes reserved, 1 byte with class (hundreds digit) in bits 0-2,
/// 1 byte with number (tens+units), followed by UTF-8 reason phrase.
fn decode_error_code(value: &[u8]) -> Result<StunAttribute, TurnError> {
    if value.len() < 4 {
        return Err(TurnError::StunParseError(
            "ERROR-CODE too short".into(),
        ));
    }

    let class = (value[2] & 0x07) as u16;
    let number = value[3] as u16;
    let code = class * 100 + number;

    let reason = if value.len() > 4 {
        String::from_utf8_lossy(&value[4..]).into_owned()
    } else {
        String::new()
    };

    Ok(StunAttribute::ErrorCode { code, reason })
}

/// Encode ERROR-CODE value bytes per RFC 5389 §15.6.
fn encode_error_code(code: u16, reason: &str) -> Vec<u8> {
    let class = (code / 100) as u8;
    let number = (code % 100) as u8;

    let reason_bytes = reason.as_bytes();
    let mut buf = Vec::with_capacity(4 + reason_bytes.len());
    buf.push(0); // reserved
    buf.push(0); // reserved
    buf.push(class & 0x07);
    buf.push(number);
    buf.extend_from_slice(reason_bytes);
    buf
}

/// Decode UNKNOWN-ATTRIBUTES (list of 16-bit attribute types).
fn decode_unknown_attributes(value: &[u8]) -> Result<StunAttribute, TurnError> {
    if value.len() % 2 != 0 {
        return Err(TurnError::StunParseError(
            "UNKNOWN-ATTRIBUTES length must be even".into(),
        ));
    }
    let mut types = Vec::with_capacity(value.len() / 2);
    for chunk in value.chunks_exact(2) {
        types.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    Ok(StunAttribute::UnknownAttributes(types))
}

/// Decode FINGERPRINT (4-byte CRC32 XOR value).
fn decode_fingerprint(value: &[u8]) -> Result<StunAttribute, TurnError> {
    if value.len() != 4 {
        return Err(TurnError::StunParseError(format!(
            "FINGERPRINT must be 4 bytes, got {}",
            value.len()
        )));
    }
    let val = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    Ok(StunAttribute::Fingerprint(val))
}

/// Decode CHANNEL-NUMBER (16-bit number + 16-bit RFFU).
fn decode_channel_number(value: &[u8]) -> Result<StunAttribute, TurnError> {
    if value.len() < 4 {
        return Err(TurnError::StunParseError(
            "CHANNEL-NUMBER too short".into(),
        ));
    }
    let num = u16::from_be_bytes([value[0], value[1]]);
    Ok(StunAttribute::ChannelNumber(num))
}

/// Decode LIFETIME (32-bit seconds).
fn decode_lifetime(value: &[u8]) -> Result<StunAttribute, TurnError> {
    if value.len() < 4 {
        return Err(TurnError::StunParseError("LIFETIME too short".into()));
    }
    let secs = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    Ok(StunAttribute::Lifetime(secs))
}

/// Decode REQUESTED-ADDRESS-FAMILY (1 byte family + 3 bytes RFFU).
fn decode_requested_address_family(value: &[u8]) -> Result<StunAttribute, TurnError> {
    if value.is_empty() {
        return Err(TurnError::StunParseError(
            "REQUESTED-ADDRESS-FAMILY empty".into(),
        ));
    }
    Ok(StunAttribute::RequestedAddressFamily(value[0]))
}

/// Decode EVEN-PORT (1 byte, R bit in most significant bit).
fn decode_even_port(value: &[u8]) -> Result<StunAttribute, TurnError> {
    if value.is_empty() {
        return Err(TurnError::StunParseError("EVEN-PORT empty".into()));
    }
    let reserve = (value[0] & 0x80) != 0;
    Ok(StunAttribute::EvenPort(reserve))
}

/// Decode REQUESTED-TRANSPORT (1 byte protocol + 3 bytes RFFU).
fn decode_requested_transport(value: &[u8]) -> Result<StunAttribute, TurnError> {
    if value.is_empty() {
        return Err(TurnError::StunParseError(
            "REQUESTED-TRANSPORT empty".into(),
        ));
    }
    Ok(StunAttribute::RequestedTransport(value[0]))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_xor_mapped_address_ipv4_roundtrip() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));
        let txn_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let encoded = encode_xor_address(&addr, &txn_id);
        let decoded = decode_xor_address(&encoded, &txn_id).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_xor_mapped_address_ipv6_roundtrip() {
        let ip = Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0, 0, 0x8a2e, 0x0370, 0x7334);
        let addr = SocketAddr::V6(SocketAddrV6::new(ip, 54321, 0, 0));
        let txn_id = [0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6];

        let encoded = encode_xor_address(&addr, &txn_id);
        let decoded = decode_xor_address(&encoded, &txn_id).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_plain_address_ipv4_roundtrip() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080));
        let encoded = encode_plain_address(&addr);
        let decoded = decode_mapped_address(&encoded).unwrap();
        if let StunAttribute::MappedAddress(decoded_addr) = decoded {
            assert_eq!(decoded_addr, addr);
        } else {
            panic!("expected MappedAddress");
        }
    }

    #[test]
    fn test_error_code_roundtrip() {
        let encoded = encode_error_code(401, "Unauthorized");
        let decoded = decode_error_code(&encoded).unwrap();
        if let StunAttribute::ErrorCode { code, reason } = decoded {
            assert_eq!(code, 401);
            assert_eq!(reason, "Unauthorized");
        } else {
            panic!("expected ErrorCode");
        }
    }

    #[test]
    fn test_error_code_438() {
        let encoded = encode_error_code(438, "Stale Nonce");
        let decoded = decode_error_code(&encoded).unwrap();
        if let StunAttribute::ErrorCode { code, reason } = decoded {
            assert_eq!(code, 438);
            assert_eq!(reason, "Stale Nonce");
        } else {
            panic!("expected ErrorCode");
        }
    }

    #[test]
    fn test_attribute_tlv_encoding() {
        let txn_id = [0u8; 12];
        let attr = StunAttribute::Username("alice".into());
        let encoded = encode_attribute(&attr, &txn_id);

        // Type (2) + Length (2) + "alice" (5) + padding (3) = 12
        assert_eq!(encoded.len(), 12);
        assert_eq!(encoded[0..2], ATTR_USERNAME.to_be_bytes());
        assert_eq!(encoded[2..4], 5u16.to_be_bytes());
        assert_eq!(&encoded[4..9], b"alice");
        assert_eq!(encoded[9], 0); // padding
        assert_eq!(encoded[10], 0);
        assert_eq!(encoded[11], 0);
    }

    #[test]
    fn test_attribute_tlv_encoding_4_byte_aligned() {
        let txn_id = [0u8; 12];
        let attr = StunAttribute::Username("test".into());
        let encoded = encode_attribute(&attr, &txn_id);

        // Type (2) + Length (2) + "test" (4) = 8, already aligned
        assert_eq!(encoded.len(), 8);
    }

    #[test]
    fn test_lifetime_roundtrip() {
        let attr = StunAttribute::Lifetime(600);
        let txn_id = [0u8; 12];
        let encoded = encode_attribute(&attr, &txn_id);

        // Type (2) + Length (2) + value (4) = 8
        assert_eq!(encoded.len(), 8);

        let decoded = decode_attribute(ATTR_LIFETIME, &encoded[4..8], &txn_id).unwrap();
        if let StunAttribute::Lifetime(secs) = decoded {
            assert_eq!(secs, 600);
        } else {
            panic!("expected Lifetime");
        }
    }

    #[test]
    fn test_channel_number_roundtrip() {
        let attr = StunAttribute::ChannelNumber(0x4000);
        let txn_id = [0u8; 12];
        let encoded = encode_attribute(&attr, &txn_id);

        // Type (2) + Length (2) + value (4) = 8
        assert_eq!(encoded.len(), 8);

        let decoded = decode_attribute(ATTR_CHANNEL_NUMBER, &encoded[4..8], &txn_id).unwrap();
        if let StunAttribute::ChannelNumber(num) = decoded {
            assert_eq!(num, 0x4000);
        } else {
            panic!("expected ChannelNumber");
        }
    }

    #[test]
    fn test_requested_transport_udp() {
        let attr = StunAttribute::RequestedTransport(17); // UDP
        let txn_id = [0u8; 12];
        let encoded = encode_attribute(&attr, &txn_id);

        let decoded = decode_attribute(ATTR_REQUESTED_TRANSPORT, &encoded[4..8], &txn_id).unwrap();
        if let StunAttribute::RequestedTransport(proto) = decoded {
            assert_eq!(proto, 17);
        } else {
            panic!("expected RequestedTransport");
        }
    }

    #[test]
    fn test_dont_fragment() {
        let attr = StunAttribute::DontFragment;
        let txn_id = [0u8; 12];
        let encoded = encode_attribute(&attr, &txn_id);

        // Type (2) + Length (2) + no value = 4
        assert_eq!(encoded.len(), 4);
        assert_eq!(encoded[2..4], 0u16.to_be_bytes()); // length = 0
    }

    #[test]
    fn test_unknown_attribute_preserved() {
        let txn_id = [0u8; 12];
        let decoded =
            decode_attribute(0xFFFF, &[0x01, 0x02, 0x03], &txn_id).unwrap();
        if let StunAttribute::Unknown { attr_type, value } = decoded {
            assert_eq!(attr_type, 0xFFFF);
            assert_eq!(value, vec![0x01, 0x02, 0x03]);
        } else {
            panic!("expected Unknown");
        }
    }

    #[test]
    fn test_message_integrity_decode() {
        let hmac = [0xAA; 20];
        let decoded = decode_message_integrity(&hmac).unwrap();
        if let StunAttribute::MessageIntegrity(h) = decoded {
            assert_eq!(h, [0xAA; 20]);
        } else {
            panic!("expected MessageIntegrity");
        }
    }

    #[test]
    fn test_message_integrity_wrong_length() {
        let result = decode_message_integrity(&[0; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_fingerprint_roundtrip() {
        let val = 0xDEADBEEF_u32;
        let encoded_value = val.to_be_bytes().to_vec();
        let decoded = decode_fingerprint(&encoded_value).unwrap();
        if let StunAttribute::Fingerprint(v) = decoded {
            assert_eq!(v, val);
        } else {
            panic!("expected Fingerprint");
        }
    }

    #[test]
    fn test_even_port_reserve_bit() {
        // R bit set
        let decoded = decode_even_port(&[0x80]).unwrap();
        if let StunAttribute::EvenPort(reserve) = decoded {
            assert!(reserve);
        } else {
            panic!("expected EvenPort");
        }

        // R bit not set
        let decoded = decode_even_port(&[0x00]).unwrap();
        if let StunAttribute::EvenPort(reserve) = decoded {
            assert!(!reserve);
        } else {
            panic!("expected EvenPort");
        }
    }

    #[test]
    fn test_unknown_attributes_list() {
        let value = vec![0x00, 0x01, 0x00, 0x20]; // MAPPED-ADDRESS, XOR-MAPPED-ADDRESS
        let decoded = decode_unknown_attributes(&value).unwrap();
        if let StunAttribute::UnknownAttributes(types) = decoded {
            assert_eq!(types, vec![0x0001, 0x0020]);
        } else {
            panic!("expected UnknownAttributes");
        }
    }
}
