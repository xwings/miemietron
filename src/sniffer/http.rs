//! HTTP/1 request targets/Host and HTTP/2 cleartext authority sniffing.
//!
//! mihomo compat: component/sniffer/http_sniffer.go. A complete authority is
//! enough; unrelated trailing headers or frame padding must not delay routing.

use loona_hpack::decoder::{DecoderError, IntegerDecodingError, StringDecodingError};

use super::SniffAttempt;

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_LEN: usize = 9;
const MAX_FRAME_LEN: usize = 1 << 14;
const MAX_HEADER_BLOCK_LEN: usize = 64 * 1024;
const HEADERS: u8 = 1;
const SETTINGS: u8 = 4;
const CONTINUATION: u8 = 9;
const ACK: u8 = 1;
const END_HEADERS: u8 = 4;
const PADDED: u8 = 8;
const PRIORITY: u8 = 0x20;
const METHODS: &[&[u8]] = &[
    b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"CONNECT", b"PATCH", b"TRACE",
];

pub(super) fn sniff_http(data: &[u8]) -> SniffAttempt {
    if data.len() < H2_PREFACE.len() && H2_PREFACE.starts_with(data) {
        return SniffAttempt::NeedMore(data.len() + 1);
    }
    if data.starts_with(H2_PREFACE) {
        sniff_http2(data)
    } else {
        sniff_http1(data)
    }
}

fn sniff_http1(data: &[u8]) -> SniffAttempt {
    let Some(space) = data.iter().position(|b| *b == b' ') else {
        return if METHODS.iter().any(|m| {
            m.get(..data.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(data))
        }) {
            SniffAttempt::NeedMore(data.len() + 1)
        } else {
            SniffAttempt::Fail
        };
    };
    if !METHODS
        .iter()
        .any(|m| m.eq_ignore_ascii_case(&data[..space]))
    {
        return SniffAttempt::Fail;
    }
    let Some(line_end) = find(data, b"\r\n") else {
        return SniffAttempt::NeedMore(data.len() + 1);
    };
    if line_end < 14 || space >= line_end {
        return SniffAttempt::Fail;
    }
    let rest = &data[space + 1..line_end];
    let Some(uri_end) = rest.iter().position(|b| *b == b' ') else {
        return SniffAttempt::Fail;
    };
    let mut uri = &rest[..uri_end];
    if uri.is_empty() {
        return SniffAttempt::Fail;
    }
    if !matches!(uri[0], b'/' | b'*') {
        if let Some(scheme) = find(uri, b"://") {
            uri = &uri[scheme + 3..];
        }
        if let Some(end) = uri.iter().position(|b| matches!(b, b'/' | b'?' | b'#')) {
            uri = &uri[..end];
        }
        if let Some(at) = uri.iter().position(|b| *b == b'@') {
            uri = &uri[at + 1..];
        }
        if let Some(host) = parse_host(uri) {
            return SniffAttempt::Found(host);
        }
    }

    let mut remaining = data;
    loop {
        let Some(end) = find(remaining, b"\r\n") else {
            return SniffAttempt::NeedMore(data.len() + 1);
        };
        let line = &remaining[..end];
        remaining = &remaining[end + 2..];
        if line.is_empty() {
            return SniffAttempt::Fail;
        }
        if let Some(colon) = line.iter().position(|b| *b == b':') {
            if line[..colon].eq_ignore_ascii_case(b"host") {
                return found_host(&line[colon + 1..], true);
            }
        }
    }
}

fn sniff_http2(data: &[u8]) -> SniffAttempt {
    let mut offset = H2_PREFACE.len();
    let mut header_stream = 0;
    let mut block = Vec::new();
    loop {
        if data.len() - offset < FRAME_HEADER_LEN {
            return SniffAttempt::NeedMore(offset + FRAME_HEADER_LEN);
        }
        let header = &data[offset..offset + FRAME_HEADER_LEN];
        let length =
            ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
        let frame_type = header[3];
        let flags = header[4];
        let stream = u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
        if offset == H2_PREFACE.len() && (frame_type != SETTINGS || flags & ACK != 0) {
            return SniffAttempt::Fail;
        }
        if length > MAX_FRAME_LEN {
            return SniffAttempt::Fail;
        }
        if frame_type == SETTINGS
            && (stream != 0
                || (flags & ACK != 0 && length != 0)
                || (flags & ACK == 0 && length % 6 != 0))
        {
            return SniffAttempt::Fail;
        }
        if header_stream == 0 {
            if frame_type == CONTINUATION || (frame_type == HEADERS && stream == 0) {
                return SniffAttempt::Fail;
            }
        } else if frame_type != CONTINUATION || stream != header_stream {
            return SniffAttempt::Fail;
        }
        let payload = offset + FRAME_HEADER_LEN;
        if header_stream == 0 {
            if frame_type != HEADERS {
                if data.len() - payload < length {
                    return SniffAttempt::NeedMore(payload + length);
                }
                offset = payload + length;
                continue;
            }
            header_stream = stream;
        }

        let mut fragment_start = 0;
        let mut fragment_end = length;
        if frame_type == HEADERS {
            if flags & PADDED != 0 {
                if length == 0 {
                    return SniffAttempt::Fail;
                }
                let Some(&padding) = data.get(payload) else {
                    return SniffAttempt::NeedMore(payload + 1);
                };
                if padding as usize >= length {
                    return SniffAttempt::Fail;
                }
                fragment_start += 1;
                fragment_end -= padding as usize;
            }
            if flags & PRIORITY != 0 {
                if fragment_end - fragment_start < 5 {
                    return SniffAttempt::Fail;
                }
                fragment_start += 5;
            }
        }
        let available_end = (data.len() - payload).min(fragment_end);
        if available_end > fragment_start {
            let fragment = &data[payload + fragment_start..payload + available_end];
            if fragment.len() > MAX_HEADER_BLOCK_LEN - block.len() {
                return SniffAttempt::Fail;
            }
            block.extend_from_slice(fragment);
            match decode_authority(&block) {
                SniffAttempt::NeedMore(_) => {}
                verdict => return verdict,
            }
        }
        if flags & END_HEADERS != 0
            && (fragment_start == fragment_end || available_end == fragment_end)
        {
            return SniffAttempt::Fail;
        }
        if data.len() - payload < length {
            let wanted = if available_end < fragment_end {
                if data.len() - payload < fragment_start {
                    payload + fragment_start + 1
                } else {
                    data.len() + 1
                }
            } else {
                payload + length
            };
            return SniffAttempt::NeedMore(wanted);
        }
        offset = payload + length;
    }
}

fn decode_authority(block: &[u8]) -> SniffAttempt {
    // Rebuild from the bounded header prefix when another frame arrives. The
    // decoder's dynamic table then includes only complete preceding fields;
    // an incomplete literal can never change state before being retried.
    let mut decoder = loona_hpack::Decoder::new();
    decoder.set_max_allowed_table_size(4096);
    let mut authority = None;
    let mut host = None;
    let result = decoder.decode_with_cb(block, |name, value| match name.as_ref() {
        b":authority" => authority = Some(value.into_owned()),
        b"host" => host = Some(value.into_owned()),
        _ => {}
    });
    if let Some(value) = authority
        .filter(|value| !value.is_empty())
        .or(host.filter(|value| !value.is_empty()))
    {
        return found_host(&value, false);
    }
    match result {
        Ok(())
        | Err(DecoderError::SizeUpdateAtEnd)
        | Err(DecoderError::IntegerDecodingError(IntegerDecodingError::NotEnoughOctets))
        | Err(DecoderError::StringDecodingError(StringDecodingError::NotEnoughOctets)) => {
            SniffAttempt::NeedMore(block.len() + 1)
        }
        Err(_) => SniffAttempt::Fail,
    }
}

fn found_host(value: &[u8], trim_space: bool) -> SniffAttempt {
    let value = if trim_space {
        match std::str::from_utf8(value) {
            Ok(value) => value.trim().as_bytes(),
            Err(_) => return SniffAttempt::Fail,
        }
    } else {
        value
    };
    match parse_host(value) {
        Some(host) => SniffAttempt::Found(host),
        None => SniffAttempt::Fail,
    }
}

fn parse_host(value: &[u8]) -> Option<String> {
    let mut host = std::str::from_utf8(value).ok()?;
    // Go's net.SplitHostPort accepts a textual port; domain validation occurs
    // later in the dispatcher. IPv6 literals are rejected below in either form.
    if let Some(rest) = host.strip_prefix('[') {
        if let Some((inside, suffix)) = rest.split_once(']') {
            if suffix.is_empty() || (suffix.starts_with(':') && !suffix[1..].contains(':')) {
                host = inside;
            }
        }
    } else if let Some((name, port)) = host.split_once(':') {
        if !port.contains(':') {
            host = name;
        }
    }
    let host = host.trim_end_matches('.').to_lowercase();
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(host)
    }
}

fn find(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len()).position(|part| part == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(data: &[u8]) -> Option<String> {
        match sniff_http(data) {
            SniffAttempt::Found(host) => Some(host),
            _ => None,
        }
    }

    fn frame(frame_type: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut frame = vec![
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
            frame_type,
            flags,
        ];
        frame.extend_from_slice(&stream.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn h2(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut data = H2_PREFACE.to_vec();
        data.extend(frame(SETTINGS, 0, 0, &[]));
        for frame in frames {
            data.extend(frame);
        }
        data
    }

    fn rfc_huffman_block() -> Vec<u8> {
        // RFC 7541 C.4.1, independent of the decoder used by this module.
        hex::decode("828684418cf1e3c2e5f23a6ba0ab90f4ff").unwrap()
    }

    #[test]
    fn http1_recovers_request_authority_and_waits_for_fragmented_host() {
        for (request, expected) in [
            ("CONNECT Proxy.Example.:443 HTTP/1.1\r\n", "proxy.example"),
            (
                "get https://user@Absolute.Example.:8443/a?x HTTP/1.1\r\nHost: ignored.example\r\n",
                "absolute.example",
            ),
            (
                "GET http://127.0.0.1/a HTTP/1.1\r\nHost: fallback.example\r\n",
                "fallback.example",
            ),
        ] {
            assert_eq!(host(request.as_bytes()).as_deref(), Some(expected));
        }
        let request = b"GET / HTTP/1.1\r\nHost: split.example\r\n";
        for len in 0..request.len() {
            assert!(matches!(sniff_http(&request[..len]), SniffAttempt::NeedMore(n) if n > len));
        }
        assert_eq!(host(request).as_deref(), Some("split.example"));
        assert!(matches!(
            sniff_http(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"),
            SniffAttempt::Fail
        ));
    }

    #[test]
    fn h2_huffman_authority_survives_fragmented_continuations() {
        let block = rfc_huffman_block();
        for split in 1..block.len() {
            let data = h2(&[
                frame(HEADERS, 0, 1, &block[..split]),
                frame(CONTINUATION, END_HEADERS, 1, &block[split..]),
            ]);
            for len in 0..data.len() {
                assert!(
                    matches!(sniff_http(&data[..len]), SniffAttempt::NeedMore(n) if n > len),
                    "split={split}, len={len}"
                );
            }
            assert_eq!(host(&data).as_deref(), Some("www.example.com"));
        }
    }

    #[test]
    fn h2_authority_is_available_before_trailing_payload_or_padding() {
        let mut block = rfc_huffman_block();
        block.push(0x80); // Invalid trailing index cannot improve the authority.
        let data = h2(&[frame(HEADERS, END_HEADERS, 1, &block)]);
        assert_eq!(host(&data).as_deref(), Some("www.example.com"));

        let block = rfc_huffman_block();
        let mut payload = vec![16, 0, 0, 0, 0, 0]; // PADDED + PRIORITY
        payload.extend(&block);
        payload.extend([0; 16]);
        let mut data = h2(&[frame(HEADERS, END_HEADERS | PADDED | PRIORITY, 1, &payload)]);
        data.truncate(data.len() - 16);
        assert_eq!(host(&data).as_deref(), Some("www.example.com"));

        let mut data = h2(&[frame(
            HEADERS,
            END_HEADERS,
            1,
            &[block.as_slice(), &[0; 128]].concat(),
        )]);
        data.truncate(data.len() - 128);
        assert_eq!(host(&data).as_deref(), Some("www.example.com"));
    }

    #[test]
    fn h2_validates_frame_boundaries_and_rejects_bad_hpack() {
        let block = rfc_huffman_block();
        let cases = [
            [H2_PREFACE, &frame(HEADERS, 0, 1, &[])].concat(),
            [H2_PREFACE, &frame(SETTINGS, ACK, 0, &[])].concat(),
            [H2_PREFACE, &frame(SETTINGS, 0, 1, &[])].concat(),
            [H2_PREFACE, &frame(SETTINGS, 0, 0, &[0])].concat(),
            h2(&[frame(HEADERS, 0, 0, &block)]),
            h2(&[frame(CONTINUATION, 0, 1, &block)]),
            h2(&[
                frame(HEADERS, 0, 1, &block[..4]),
                frame(CONTINUATION, END_HEADERS, 3, &block[4..]),
            ]),
            h2(&[
                frame(HEADERS, 0, 1, &block[..4]),
                frame(SETTINGS, 0, 0, &[]),
            ]),
            h2(&[frame(HEADERS, END_HEADERS | PADDED, 1, &[1])]),
            h2(&[frame(HEADERS, END_HEADERS, 1, &[0x80])]),
            h2(&[frame(HEADERS, END_HEADERS, 1, &[0x3f, 0xe2, 0x1f])]), // table >4096
        ];
        for (index, data) in cases.iter().enumerate() {
            assert!(
                matches!(sniff_http(data), SniffAttempt::Fail),
                "case {index}"
            );
        }
        let mut oversized = frame(HEADERS, 0, 1, &vec![0; MAX_FRAME_LEN + 1]);
        oversized.truncate(FRAME_HEADER_LEN);
        assert!(matches!(sniff_http(&h2(&[oversized])), SniffAttempt::Fail));

        // A truncated table-size integer must wait rather than panic.
        let data = h2(&[frame(HEADERS, 0, 1, &[0x3f])]);
        assert!(matches!(sniff_http(&data), SniffAttempt::NeedMore(_)));
    }

    #[test]
    fn h2_host_fallback_and_dynamic_authority_name() {
        for block in [
            b"\x00\x04host\x0cfallback.com".as_slice(),
            b"\x01\x00\x00\x04host\x0cfallback.com",
        ] {
            let data = h2(&[frame(HEADERS, END_HEADERS, 1, block)]);
            assert_eq!(host(&data).as_deref(), Some("fallback.com"));
        }

        // An incrementally indexed :authority name is immediately reusable.
        let mut block = b"\x40\x0a:authority\x00".to_vec();
        block.extend(b"\x7e\x0bdynamic.com"); // Dynamic index 62, literal value.
        let data = h2(&[frame(HEADERS, END_HEADERS, 1, &block)]);
        assert_eq!(host(&data).as_deref(), Some("dynamic.com"));
    }
}
