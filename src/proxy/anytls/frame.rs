//! Frame layout for the anytls session layer
//! (mihomo transport/anytls/session/frame.go).
//!
//! Each frame is `[cmd:1][sid:4][length:2][data:length]` big-endian.

#![allow(dead_code)]

// Commands
pub const CMD_WASTE: u8 = 0; // padding
pub const CMD_SYN: u8 = 1; // stream open
pub const CMD_PSH: u8 = 2; // data push
pub const CMD_FIN: u8 = 3; // stream close / EOF
pub const CMD_SETTINGS: u8 = 4; // client->server settings
pub const CMD_ALERT: u8 = 5; // alert
pub const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
// Since version 2
pub const CMD_SYNACK: u8 = 7;
pub const CMD_HEART_REQUEST: u8 = 8;
pub const CMD_HEART_RESPONSE: u8 = 9;
pub const CMD_SERVER_SETTINGS: u8 = 10;

pub const HEADER_OVERHEAD: usize = 1 + 4 + 2;

/// Encode a frame header into a 7-byte buffer.
#[inline]
pub fn encode_header(cmd: u8, sid: u32, length: u16) -> [u8; HEADER_OVERHEAD] {
    let mut hdr = [0u8; HEADER_OVERHEAD];
    hdr[0] = cmd;
    hdr[1..5].copy_from_slice(&sid.to_be_bytes());
    hdr[5..7].copy_from_slice(&length.to_be_bytes());
    hdr
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub cmd: u8,
    pub sid: u32,
    pub length: u16,
}

impl Header {
    pub fn parse(buf: &[u8; HEADER_OVERHEAD]) -> Self {
        Self {
            cmd: buf[0],
            sid: u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
            length: u16::from_be_bytes([buf[5], buf[6]]),
        }
    }
}

/// mihomo util.StringMap serialization: `key=value\n...`. Ordering is not
/// specified by the protocol.
pub fn encode_string_map(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    for (k, v) in entries {
        out.extend_from_slice(k.as_bytes());
        out.push(b'=');
        out.extend_from_slice(v.as_bytes());
        out.push(b'\n');
    }
    out
}

/// Parse a mihomo util.StringMap.
pub fn decode_string_map(data: &[u8]) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let Ok(text) = std::str::from_utf8(data) else {
        return out;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let hdr = encode_header(CMD_PSH, 0x01020304, 0x1234);
        assert_eq!(hdr, [CMD_PSH, 1, 2, 3, 4, 0x12, 0x34]);
        let parsed = Header::parse(&hdr);
        assert_eq!(parsed.cmd, CMD_PSH);
        assert_eq!(parsed.sid, 0x01020304);
        assert_eq!(parsed.length, 0x1234);
    }

    #[test]
    fn string_map_roundtrip() {
        let enc = encode_string_map(&[("v", "2"), ("padding-md5", "abcd")]);
        let dec = decode_string_map(&enc);
        assert_eq!(dec.get("v").unwrap(), "2");
        assert_eq!(dec.get("padding-md5").unwrap(), "abcd");
    }
}
