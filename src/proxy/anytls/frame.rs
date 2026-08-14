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

/// Maximum payload bytes per data frame. The header encodes the payload length
/// as a u16, so a single frame cannot carry more than 65535 bytes.
/// mihomo compat: session.go maxFrameDataLen.
pub const MAX_FRAME_DATA_LEN: usize = 0xFFFF;

/// Encode `data` as a sequence of PSH frames for `sid`, splitting every
/// [`MAX_FRAME_DATA_LEN`] bytes. The caller writes the result in a single
/// call so one stream write stays contiguous against other frames.
/// mihomo compat: session.go writeDataFrame.
pub fn encode_data_frames(sid: u32, data: &[u8]) -> Vec<u8> {
    let frame_count = data.len().div_ceil(MAX_FRAME_DATA_LEN);
    let mut buf = Vec::with_capacity(data.len() + frame_count * HEADER_OVERHEAD);
    for chunk in data.chunks(MAX_FRAME_DATA_LEN) {
        buf.extend_from_slice(&encode_header(CMD_PSH, sid, chunk.len() as u16));
        buf.extend_from_slice(chunk);
    }
    buf
}

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

    /// Walk a frame sequence, returning (length-field, payload-len) per frame
    /// and asserting the framing is self-consistent end to end.
    fn parse_frames(buf: &[u8], sid: u32) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < buf.len() {
            let hdr: [u8; HEADER_OVERHEAD] = buf[i..i + HEADER_OVERHEAD].try_into().unwrap();
            let h = Header::parse(&hdr);
            assert_eq!(h.cmd, CMD_PSH);
            assert_eq!(h.sid, sid);
            i += HEADER_OVERHEAD;
            let len = h.length as usize;
            assert!(i + len <= buf.len(), "frame payload overruns buffer");
            out.push((len, len));
            i += len;
        }
        out
    }

    #[test]
    fn data_frames_single_when_under_limit() {
        let data = vec![0xAB; 1024];
        let buf = encode_data_frames(7, &data);
        assert_eq!(buf.len(), HEADER_OVERHEAD + data.len());
        assert_eq!(parse_frames(&buf, 7), vec![(1024, 1024)]);
        assert_eq!(&buf[HEADER_OVERHEAD..], &data[..]);
    }

    #[test]
    fn data_frames_exactly_at_limit_stays_single() {
        let data = vec![0xCD; MAX_FRAME_DATA_LEN];
        let buf = encode_data_frames(1, &data);
        assert_eq!(
            parse_frames(&buf, 1),
            vec![(MAX_FRAME_DATA_LEN, MAX_FRAME_DATA_LEN)]
        );
    }

    /// The header length field is a u16, so a payload one byte past the limit
    /// used to truncate to 0 and desynchronize the peer's parser.
    #[test]
    fn data_frames_split_past_limit() {
        let data: Vec<u8> = (0..MAX_FRAME_DATA_LEN + 1).map(|i| i as u8).collect();
        let buf = encode_data_frames(9, &data);
        assert_eq!(
            parse_frames(&buf, 9),
            vec![(MAX_FRAME_DATA_LEN, 65535), (1, 1)]
        );
        // Payload survives the split byte-for-byte, in order.
        let mut rejoined = Vec::new();
        rejoined.extend_from_slice(&buf[HEADER_OVERHEAD..HEADER_OVERHEAD + MAX_FRAME_DATA_LEN]);
        rejoined.extend_from_slice(&buf[2 * HEADER_OVERHEAD + MAX_FRAME_DATA_LEN..]);
        assert_eq!(rejoined, data);
    }

    #[test]
    fn data_frames_split_multiple_chunks() {
        let data = vec![0x11; MAX_FRAME_DATA_LEN * 2 + 500];
        let buf = encode_data_frames(3, &data);
        let frames = parse_frames(&buf, 3);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].0, MAX_FRAME_DATA_LEN);
        assert_eq!(frames[1].0, MAX_FRAME_DATA_LEN);
        assert_eq!(frames[2].0, 500);
        assert_eq!(buf.len(), data.len() + 3 * HEADER_OVERHEAD);
    }

    #[test]
    fn data_frames_empty_emits_nothing() {
        assert!(encode_data_frames(1, &[]).is_empty());
    }

    #[test]
    fn string_map_roundtrip() {
        let enc = encode_string_map(&[("v", "2"), ("padding-md5", "abcd")]);
        let dec = decode_string_map(&enc);
        assert_eq!(dec.get("v").unwrap(), "2");
        assert_eq!(dec.get("padding-md5").unwrap(), "abcd");
    }
}
