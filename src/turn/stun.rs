// STUN message parser and serializer per RFC 5389
//
// Implements the STUN message format with support for TURN methods (RFC 5766).
// Also handles ChannelData framing for TURN channel bindings.
//
// STUN message header layout (20 bytes):
//   Bytes 0-1:   Message Type (method + class encoding)
//   Bytes 2-3:   Message Length (excludes 20-byte header)
//   Bytes 4-7:   Magic Cookie (0x2112A442)
//   Bytes 8-19:  Transaction ID (96 bits)
//
// Message Type encoding (RFC 5389 §6):
//   Bits:  13 12 11 10 9  8  7  6  5  4  3  2  1  0
//          M11 M10 M9 M8 M7 C1 M6 M5 M4 C0 M3 M2 M1 M0
//   Where M0-M11 = method bits, C0-C1 = class bits.

use crate::turn::attributes::StunAttribute;
use crate::turn::error::TurnError;

/// STUN magic cookie value (RFC 5389 §6).
pub const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN header size in bytes.
pub const STUN_HEADER_SIZE: usize = 20;

/// XOR value for FINGERPRINT CRC32 (RFC 5389 §15.5).
pub const FINGERPRINT_XOR: u32 = 0x5354554e;

// ---------------------------------------------------------------------------
// Method
// ---------------------------------------------------------------------------

/// STUN/TURN method identifiers.
///
/// Methods 0x0001 (Binding) are defined in RFC 5389; the rest are
/// TURN extensions from RFC 5766.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// STUN Binding (0x0001) — NAT discovery
    Binding,
    /// TURN Allocate (0x0003) — create relay allocation
    Allocate,
    /// TURN Refresh (0x0004) — refresh allocation lifetime
    Refresh,
    /// TURN Send (0x0006) — send data indication to peer
    Send,
    /// TURN Data (0x0007) — data indication from peer
    Data,
    /// TURN CreatePermission (0x0008) — install relay permission
    CreatePermission,
    /// TURN ChannelBind (0x0009) — bind channel number to peer
    ChannelBind,
}

impl Method {
    /// Returns the 12-bit method number (M0-M11).
    pub fn as_u16(self) -> u16 {
        match self {
            Method::Binding => 0x0001,
            Method::Allocate => 0x0003,
            Method::Refresh => 0x0004,
            Method::Send => 0x0006,
            Method::Data => 0x0007,
            Method::CreatePermission => 0x0008,
            Method::ChannelBind => 0x0009,
        }
    }

    /// Parses a 12-bit method number into a [`Method`].
    pub fn from_u16(val: u16) -> Result<Self, TurnError> {
        match val {
            0x0001 => Ok(Method::Binding),
            0x0003 => Ok(Method::Allocate),
            0x0004 => Ok(Method::Refresh),
            0x0006 => Ok(Method::Send),
            0x0007 => Ok(Method::Data),
            0x0008 => Ok(Method::CreatePermission),
            0x0009 => Ok(Method::ChannelBind),
            _ => Err(TurnError::StunParseError(format!(
                "unknown STUN method: 0x{:04x}",
                val
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Class
// ---------------------------------------------------------------------------

/// STUN message class (RFC 5389 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Request (C0=0, C1=0)
    Request,
    /// Indication (C0=1, C1=0)
    Indication,
    /// Success Response (C0=0, C1=1)
    SuccessResponse,
    /// Error Response (C0=1, C1=1)
    ErrorResponse,
}

impl Class {
    /// Returns the 2-bit class value (C0 in bit 0, C1 in bit 1).
    pub fn as_u8(self) -> u8 {
        match self {
            Class::Request => 0b00,
            Class::Indication => 0b01,
            Class::SuccessResponse => 0b10,
            Class::ErrorResponse => 0b11,
        }
    }

    /// Parses a 2-bit class value.
    pub fn from_u8(val: u8) -> Result<Self, TurnError> {
        match val & 0x03 {
            0b00 => Ok(Class::Request),
            0b01 => Ok(Class::Indication),
            0b10 => Ok(Class::SuccessResponse),
            0b11 => Ok(Class::ErrorResponse),
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// MessageType
// ---------------------------------------------------------------------------

/// Combined STUN message type (method + class).
///
/// The 14-bit message type field encodes both the method and class with
/// an interleaved bit layout per RFC 5389 §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageType {
    pub method: Method,
    pub class: Class,
}

impl MessageType {
    pub fn new(method: Method, class: Class) -> Self {
        Self { method, class }
    }

    /// Encode method + class into the 14-bit STUN message type field.
    ///
    /// Bit layout of the 16-bit type field (top 2 bits always 0 for STUN):
    /// ```text
    /// 15 14 | 13 12 11 10  9 |  8 |  7  6  5 |  4 |  3  2  1  0
    ///  0  0 | M11 M10 M9 M8 M7 | C1 | M6 M5 M4 | C0 | M3 M2 M1 M0
    /// ```
    pub fn to_u16(self) -> u16 {
        let m = self.method.as_u16();
        let c = self.class.as_u8() as u16;

        // Extract method bit groups
        let m0_3 = m & 0x000F; // bits 0-3
        let m4_6 = (m >> 4) & 0x0007; // bits 4-6
        let m7_11 = (m >> 7) & 0x001F; // bits 7-11

        // Extract class bits
        let c0 = c & 0x01;
        let c1 = (c >> 1) & 0x01;

        // Assemble: M0-M3 in bits 0-3, C0 in bit 4, M4-M6 in bits 5-7,
        //           C1 in bit 8, M7-M11 in bits 9-13
        m0_3 | (c0 << 4) | (m4_6 << 5) | (c1 << 8) | (m7_11 << 9)
    }

    /// Decode the 14-bit STUN message type field into method + class.
    pub fn from_u16(val: u16) -> Result<Self, TurnError> {
        // Top 2 bits must be 00 for STUN messages
        if val & 0xC000 != 0 {
            return Err(TurnError::StunParseError(
                "top 2 bits of message type must be 00 for STUN".into(),
            ));
        }

        // Extract class bits
        let c0 = (val >> 4) & 0x01;
        let c1 = (val >> 8) & 0x01;
        let class_bits = (c0 | (c1 << 1)) as u8;

        // Extract method bits
        let m0_3 = val & 0x000F;
        let m4_6 = (val >> 5) & 0x0007;
        let m7_11 = (val >> 9) & 0x001F;
        let method_bits = m0_3 | (m4_6 << 4) | (m7_11 << 7);

        Ok(MessageType {
            method: Method::from_u16(method_bits)?,
            class: Class::from_u8(class_bits)?,
        })
    }
}

// ---------------------------------------------------------------------------
// StunMessage
// ---------------------------------------------------------------------------

/// A parsed STUN message with header fields and attributes.
///
/// The wire format is a 20-byte header followed by zero or more TLV-encoded
/// attributes. The message length field in the header covers only the
/// attribute portion (not the 20-byte header itself).
#[derive(Debug, Clone)]
pub struct StunMessage {
    pub msg_type: MessageType,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<StunAttribute>,
}

impl StunMessage {
    /// Create a new STUN message with the given type and transaction ID.
    pub fn new(msg_type: MessageType, transaction_id: [u8; 12]) -> Self {
        Self {
            msg_type,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    /// Create a new STUN message with a random transaction ID.
    pub fn new_random(msg_type: MessageType) -> Self {
        let mut transaction_id = [0u8; 12];
        // Use simple random fill; callers with `rand` can use proper RNG
        #[cfg(feature = "rand")]
        {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut transaction_id);
        }
        #[cfg(not(feature = "rand"))]
        {
            // Fallback: use std time-based entropy (not cryptographically secure,
            // but sufficient for transaction IDs in development/testing)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let seed = now.as_nanos();
            for (i, byte) in transaction_id.iter_mut().enumerate() {
                *byte = ((seed >> (i * 5)) & 0xFF) as u8;
            }
        }
        Self {
            msg_type,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    /// Add an attribute to the message.
    pub fn add_attribute(&mut self, attr: StunAttribute) {
        self.attributes.push(attr);
    }

    /// Decode a STUN message from raw bytes.
    ///
    /// Validates the magic cookie and parses the header and all TLV attributes.
    /// Returns an error if the message is truncated, has an invalid cookie,
    /// or contains malformed attributes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TurnError> {
        if bytes.len() < STUN_HEADER_SIZE {
            return Err(TurnError::StunParseError(format!(
                "message too short: {} bytes, need at least {}",
                bytes.len(),
                STUN_HEADER_SIZE
            )));
        }

        // Parse message type (first 2 bytes)
        let type_val = u16::from_be_bytes([bytes[0], bytes[1]]);
        let msg_type = MessageType::from_u16(type_val)?;

        // Parse message length (bytes 2-3) — length of attributes only
        let msg_length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;

        // Validate magic cookie (bytes 4-7)
        let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(TurnError::StunParseError(format!(
                "invalid magic cookie: 0x{:08x}, expected 0x{:08x}",
                cookie, MAGIC_COOKIE
            )));
        }

        // Extract transaction ID (bytes 8-19)
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&bytes[8..20]);

        // Validate total length
        let total_expected = STUN_HEADER_SIZE + msg_length;
        if bytes.len() < total_expected {
            return Err(TurnError::StunParseError(format!(
                "message truncated: have {} bytes, header says {}",
                bytes.len(),
                total_expected
            )));
        }

        // Parse attributes from the body
        let attr_bytes = &bytes[STUN_HEADER_SIZE..total_expected];
        let attributes = Self::decode_attributes(attr_bytes, &transaction_id)?;

        Ok(StunMessage {
            msg_type,
            transaction_id,
            attributes,
        })
    }

    /// Parse the TLV attribute list from the message body.
    fn decode_attributes(
        mut data: &[u8],
        transaction_id: &[u8; 12],
    ) -> Result<Vec<StunAttribute>, TurnError> {
        let mut attributes = Vec::new();

        while data.len() >= 4 {
            // Each attribute: type (2 bytes) + length (2 bytes) + value + padding
            let attr_type = u16::from_be_bytes([data[0], data[1]]);
            let attr_len = u16::from_be_bytes([data[2], data[3]]) as usize;

            if data.len() < 4 + attr_len {
                return Err(TurnError::StunParseError(format!(
                    "attribute 0x{:04x} truncated: need {} bytes, have {}",
                    attr_type,
                    attr_len,
                    data.len() - 4
                )));
            }

            let attr_value = &data[4..4 + attr_len];
            let attr = crate::turn::attributes::decode_attribute(
                attr_type,
                attr_value,
                transaction_id,
            )?;
            attributes.push(attr);

            // Advance past value + padding to 4-byte boundary
            let padded_len = (attr_len + 3) & !3;
            let total_attr_size = 4 + padded_len;
            if total_attr_size > data.len() {
                break;
            }
            data = &data[total_attr_size..];
        }

        Ok(attributes)
    }

    /// Encode this STUN message into wire format bytes.
    ///
    /// The message length field is computed from the encoded attributes.
    /// Attributes are TLV-encoded with 4-byte padding.
    pub fn encode(&self) -> Vec<u8> {
        // Encode all attributes first to determine total length
        let mut attr_bytes = Vec::new();
        for attr in &self.attributes {
            let encoded = crate::turn::attributes::encode_attribute(attr, &self.transaction_id);
            attr_bytes.extend_from_slice(&encoded);
        }

        let msg_length = attr_bytes.len() as u16;

        // Build the 20-byte header
        let mut buf = Vec::with_capacity(STUN_HEADER_SIZE + attr_bytes.len());

        // Message type (2 bytes)
        buf.extend_from_slice(&self.msg_type.to_u16().to_be_bytes());
        // Message length (2 bytes)
        buf.extend_from_slice(&msg_length.to_be_bytes());
        // Magic cookie (4 bytes)
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        // Transaction ID (12 bytes)
        buf.extend_from_slice(&self.transaction_id);
        // Attributes
        buf.extend_from_slice(&attr_bytes);

        buf
    }

    /// Encode the message, computing the correct length field as if a
    /// MESSAGE-INTEGRITY attribute of 24 bytes (4-byte TLV header + 20-byte HMAC)
    /// will be appended. This is used to generate the bytes over which
    /// MESSAGE-INTEGRITY is computed per RFC 5389 §15.4.
    ///
    /// The returned bytes do NOT include the MESSAGE-INTEGRITY attribute itself.
    pub fn encode_for_integrity(&self) -> Vec<u8> {
        // Encode attributes up to (but not including) MESSAGE-INTEGRITY
        let mut attr_bytes = Vec::new();
        for attr in &self.attributes {
            if matches!(attr, StunAttribute::MessageIntegrity(_)) {
                break;
            }
            if matches!(attr, StunAttribute::Fingerprint(_)) {
                break;
            }
            let encoded = crate::turn::attributes::encode_attribute(attr, &self.transaction_id);
            attr_bytes.extend_from_slice(&encoded);
        }

        // The length field must include the MESSAGE-INTEGRITY attribute that will follow
        // (4 bytes TLV header + 20 bytes HMAC = 24 bytes)
        let msg_length = (attr_bytes.len() + 24) as u16;

        let mut buf = Vec::with_capacity(STUN_HEADER_SIZE + attr_bytes.len());
        buf.extend_from_slice(&self.msg_type.to_u16().to_be_bytes());
        buf.extend_from_slice(&msg_length.to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&self.transaction_id);
        buf.extend_from_slice(&attr_bytes);

        buf
    }

    /// Encode the message for FINGERPRINT computation per RFC 5389 §15.5.
    ///
    /// Returns all bytes up to (but not including) the FINGERPRINT attribute,
    /// with the length field adjusted to include the FINGERPRINT (8 bytes).
    pub fn encode_for_fingerprint(&self) -> Vec<u8> {
        // Encode all attributes except FINGERPRINT
        let mut attr_bytes = Vec::new();
        for attr in &self.attributes {
            if matches!(attr, StunAttribute::Fingerprint(_)) {
                break;
            }
            let encoded = crate::turn::attributes::encode_attribute(attr, &self.transaction_id);
            attr_bytes.extend_from_slice(&encoded);
        }

        // Length includes the FINGERPRINT attribute (4 header + 4 value = 8 bytes)
        let msg_length = (attr_bytes.len() + 8) as u16;

        let mut buf = Vec::with_capacity(STUN_HEADER_SIZE + attr_bytes.len());
        buf.extend_from_slice(&self.msg_type.to_u16().to_be_bytes());
        buf.extend_from_slice(&msg_length.to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&self.transaction_id);
        buf.extend_from_slice(&attr_bytes);

        buf
    }

    /// Find the first attribute of a given type in the message.
    pub fn get_attribute(&self, predicate: impl Fn(&StunAttribute) -> bool) -> Option<&StunAttribute> {
        self.attributes.iter().find(|a| predicate(a))
    }

    /// Get the USERNAME attribute value, if present.
    pub fn get_username(&self) -> Option<&str> {
        for attr in &self.attributes {
            if let StunAttribute::Username(ref u) = attr {
                return Some(u.as_str());
            }
        }
        None
    }

    /// Get the REALM attribute value, if present.
    pub fn get_realm(&self) -> Option<&str> {
        for attr in &self.attributes {
            if let StunAttribute::Realm(ref r) = attr {
                return Some(r.as_str());
            }
        }
        None
    }

    /// Get the NONCE attribute value, if present.
    pub fn get_nonce(&self) -> Option<&str> {
        for attr in &self.attributes {
            if let StunAttribute::Nonce(ref n) = attr {
                return Some(n.as_str());
            }
        }
        None
    }

    /// Get the MESSAGE-INTEGRITY attribute value, if present.
    pub fn get_message_integrity(&self) -> Option<&[u8; 20]> {
        for attr in &self.attributes {
            if let StunAttribute::MessageIntegrity(ref mi) = attr {
                return Some(mi);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// ChannelData
// ---------------------------------------------------------------------------

/// ChannelData message for TURN channel bindings (RFC 5766 §11.4).
///
/// ChannelData uses a compact 4-byte header instead of the STUN format:
///   Bytes 0-1: Channel Number (0x4000-0x7FFF)
///   Bytes 2-3: Data Length
///   Bytes 4+:  Application Data (padded to 4 bytes over UDP)
#[derive(Debug, Clone)]
pub struct ChannelData {
    pub channel_number: u16,
    pub data: Vec<u8>,
}

impl ChannelData {
    /// Decode a ChannelData message from raw bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TurnError> {
        if bytes.len() < 4 {
            return Err(TurnError::StunParseError(
                "ChannelData message too short".into(),
            ));
        }

        let channel_number = u16::from_be_bytes([bytes[0], bytes[1]]);
        let data_length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;

        // Channel numbers must be in range 0x4000-0x7FFF
        if !(0x4000..=0x7FFF).contains(&channel_number) {
            return Err(TurnError::StunParseError(format!(
                "invalid channel number: 0x{:04x}, must be in 0x4000-0x7FFF",
                channel_number
            )));
        }

        if bytes.len() < 4 + data_length {
            return Err(TurnError::StunParseError(format!(
                "ChannelData truncated: need {} data bytes, have {}",
                data_length,
                bytes.len() - 4
            )));
        }

        let data = bytes[4..4 + data_length].to_vec();

        Ok(ChannelData {
            channel_number,
            data,
        })
    }

    /// Encode this ChannelData message into wire format.
    ///
    /// The data portion is padded to a 4-byte boundary (for UDP transport).
    pub fn encode(&self) -> Vec<u8> {
        let data_len = self.data.len();
        let padded_len = (data_len + 3) & !3;
        let mut buf = Vec::with_capacity(4 + padded_len);

        buf.extend_from_slice(&self.channel_number.to_be_bytes());
        buf.extend_from_slice(&(data_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.data);

        // Pad to 4-byte boundary with zeros
        let padding = padded_len - data_len;
        for _ in 0..padding {
            buf.push(0);
        }

        buf
    }
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the buffer begins with a ChannelData message
/// (first two bits are NOT `00`).
///
/// STUN messages always have the first two bits as `00` (message type field).
/// ChannelData starts with channel numbers 0x4000-0x7FFF, which have the
/// first two bits as `01`.
pub fn is_channel_data(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    // First two bits: 00 = STUN, 01 = ChannelData
    (bytes[0] & 0xC0) != 0x00
}

/// Returns `true` if the buffer looks like a valid STUN message
/// (first two bits are `00` and magic cookie is present).
pub fn is_stun_message(bytes: &[u8]) -> bool {
    if bytes.len() < STUN_HEADER_SIZE {
        return false;
    }
    // First two bits must be 00
    if (bytes[0] & 0xC0) != 0x00 {
        return false;
    }
    // Check magic cookie
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    cookie == MAGIC_COOKIE
}

/// Compute the CRC32 fingerprint value for a STUN message.
///
/// The fingerprint is `CRC32(message_bytes) XOR 0x5354554e` per RFC 5389 §15.5.
/// `message_bytes` should be the entire message up to (but not including)
/// the FINGERPRINT attribute, with the length field adjusted to include it.
pub fn compute_fingerprint(message_bytes: &[u8]) -> u32 {
    let crc = crc32_compute(message_bytes);
    crc ^ FINGERPRINT_XOR
}

/// Simple CRC32 (ISO 3309 / ITU-T V.42) implementation.
///
/// This uses the standard polynomial 0xEDB88320 (reflected form).
/// In production, the `crc32fast` crate should be used instead for
/// SIMD-accelerated performance.
fn crc32_compute(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_encoding_binding_request() {
        let mt = MessageType::new(Method::Binding, Class::Request);
        let encoded = mt.to_u16();
        assert_eq!(encoded, 0x0001);
        let decoded = MessageType::from_u16(encoded).unwrap();
        assert_eq!(decoded.method, Method::Binding);
        assert_eq!(decoded.class, Class::Request);
    }

    #[test]
    fn test_message_type_encoding_binding_success() {
        let mt = MessageType::new(Method::Binding, Class::SuccessResponse);
        let encoded = mt.to_u16();
        assert_eq!(encoded, 0x0101);
        let decoded = MessageType::from_u16(encoded).unwrap();
        assert_eq!(decoded.method, Method::Binding);
        assert_eq!(decoded.class, Class::SuccessResponse);
    }

    #[test]
    fn test_message_type_encoding_allocate_request() {
        let mt = MessageType::new(Method::Allocate, Class::Request);
        let encoded = mt.to_u16();
        assert_eq!(encoded, 0x0003);
        let decoded = MessageType::from_u16(encoded).unwrap();
        assert_eq!(decoded.method, Method::Allocate);
        assert_eq!(decoded.class, Class::Request);
    }

    #[test]
    fn test_message_type_encoding_allocate_error() {
        let mt = MessageType::new(Method::Allocate, Class::ErrorResponse);
        let encoded = mt.to_u16();
        assert_eq!(encoded, 0x0113);
        let decoded = MessageType::from_u16(encoded).unwrap();
        assert_eq!(decoded.method, Method::Allocate);
        assert_eq!(decoded.class, Class::ErrorResponse);
    }

    #[test]
    fn test_message_type_roundtrip_all_methods() {
        let methods = [
            Method::Binding,
            Method::Allocate,
            Method::Refresh,
            Method::Send,
            Method::Data,
            Method::CreatePermission,
            Method::ChannelBind,
        ];
        let classes = [
            Class::Request,
            Class::Indication,
            Class::SuccessResponse,
            Class::ErrorResponse,
        ];

        for method in &methods {
            for class in &classes {
                let mt = MessageType::new(*method, *class);
                let encoded = mt.to_u16();
                let decoded = MessageType::from_u16(encoded).unwrap();
                assert_eq!(decoded.method, *method, "method mismatch for {:?}/{:?}", method, class);
                assert_eq!(decoded.class, *class, "class mismatch for {:?}/{:?}", method, class);
            }
        }
    }

    #[test]
    fn test_is_channel_data() {
        // STUN message: first byte has top 2 bits = 00
        assert!(!is_channel_data(&[0x00, 0x01]));
        // ChannelData: channel 0x4000 -> first byte = 0x40 -> top 2 bits = 01
        assert!(is_channel_data(&[0x40, 0x00]));
        // Empty
        assert!(!is_channel_data(&[]));
    }

    #[test]
    fn test_is_stun_message() {
        // Valid STUN header: type=0x0001, len=0, cookie=0x2112A442, txn_id=zeros
        let mut buf = [0u8; 20];
        buf[0] = 0x00;
        buf[1] = 0x01;
        // length = 0
        buf[4] = 0x21;
        buf[5] = 0x12;
        buf[6] = 0xA4;
        buf[7] = 0x42;
        assert!(is_stun_message(&buf));

        // Wrong cookie
        buf[4] = 0x00;
        assert!(!is_stun_message(&buf));
    }

    #[test]
    fn test_channel_data_roundtrip() {
        let cd = ChannelData {
            channel_number: 0x4001,
            data: vec![1, 2, 3, 4, 5],
        };
        let encoded = cd.encode();
        let decoded = ChannelData::decode(&encoded).unwrap();
        assert_eq!(decoded.channel_number, 0x4001);
        assert_eq!(decoded.data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_channel_data_padding() {
        let cd = ChannelData {
            channel_number: 0x4001,
            data: vec![1, 2, 3], // 3 bytes -> padded to 4
        };
        let encoded = cd.encode();
        // 4 header + 4 padded data = 8 bytes
        assert_eq!(encoded.len(), 8);
        assert_eq!(encoded[7], 0); // padding byte
    }

    #[test]
    fn test_stun_message_encode_decode_empty() {
        let msg = StunMessage {
            msg_type: MessageType::new(Method::Binding, Class::Request),
            transaction_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            attributes: vec![],
        };
        let encoded = msg.encode();
        assert_eq!(encoded.len(), STUN_HEADER_SIZE);

        let decoded = StunMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.msg_type.method, Method::Binding);
        assert_eq!(decoded.msg_type.class, Class::Request);
        assert_eq!(decoded.transaction_id, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert!(decoded.attributes.is_empty());
    }

    #[test]
    fn test_crc32_known_value() {
        // CRC32 of "123456789" is 0xCBF43926
        let data = b"123456789";
        let crc = crc32_compute(data);
        assert_eq!(crc, 0xCBF43926);
    }

    #[test]
    fn test_decode_too_short() {
        let result = StunMessage::decode(&[0; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_bad_cookie() {
        let mut buf = [0u8; 20];
        buf[0] = 0x00;
        buf[1] = 0x01;
        // Bad cookie
        buf[4] = 0xFF;
        let result = StunMessage::decode(&buf);
        assert!(result.is_err());
    }
}
