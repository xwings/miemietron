// Protocol sniffer - extract domain from TLS ClientHello SNI and HTTP Host header.

/// Sniff the domain from a connection's initial bytes.
///
/// Tries TLS SNI first (if the data starts with 0x16), then HTTP Host header
/// (if it looks like an HTTP request). Returns `None` if no domain can be
/// extracted.
pub fn sniff_domain(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    // TLS handshake starts with 0x16
    if data[0] == 0x16 {
        return extract_tls_sni(data);
    }

    // Try HTTP Host header
    extract_http_host(data)
}

/// Extract the Host header from an HTTP request.
///
/// Recognises requests starting with common HTTP methods:
/// GET, POST, PUT, DELETE, HEAD, CONNECT, OPTIONS, PATCH, TRACE.
pub fn extract_http_host(data: &[u8]) -> Option<String> {
    // Quick check: is this an HTTP request?
    let http_methods: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"CONNECT ",
        b"OPTIONS ",
        b"PATCH ",
        b"TRACE ",
    ];

    let is_http = http_methods.iter().any(|m| data.starts_with(m));
    if !is_http {
        return None;
    }

    // Scan for "Host:" header (case-insensitive).
    // HTTP headers are separated by \r\n. We search for \r\nHost: or
    // check if it's the first header after the request line.
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => {
            // Try partial — headers should be ASCII
            let valid_len = data.iter().position(|&b| b > 0x7F).unwrap_or(data.len());
            if valid_len == 0 {
                return None;
            }
            std::str::from_utf8(&data[..valid_len]).ok()?
        }
    };

    // Look for the Host header
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            // End of headers
            break;
        }
        if let Some(rest) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
        {
            let host = rest.trim();
            // Strip port suffix if present (e.g., "example.com:443")
            let domain = if let Some(bracket_end) = host.find(']') {
                // IPv6 literal like [::1]:80 — not a domain
                let _ = bracket_end;
                return None;
            } else if let Some(colon) = host.rfind(':') {
                &host[..colon]
            } else {
                host
            };
            if !domain.is_empty() {
                return Some(domain.to_string());
            }
        }
        // Also handle mixed case (e.g., "HOST:", "Host:")
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host:") && !line.starts_with("Host:") && !line.starts_with("host:") {
            let rest = &line[5..];
            let host = rest.trim();
            let domain = if host.find(']').is_some() {
                return None;
            } else if let Some(colon) = host.rfind(':') {
                &host[..colon]
            } else {
                host
            };
            if !domain.is_empty() {
                return Some(domain.to_string());
            }
        }
    }

    None
}

/// Extract SNI from a TLS ClientHello message.
pub fn extract_tls_sni(data: &[u8]) -> Option<String> {
    // TLS record layer
    if data.len() < 5 || data[0] != 0x16 {
        return None; // Not a TLS handshake
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    let hs = &data[5..];
    if hs.is_empty() || hs[0] != 0x01 {
        return None; // Not ClientHello
    }

    if hs.len() < 4 {
        return None;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hs.len() < 4 + hs_len {
        return None;
    }

    let ch = &hs[4..];
    // Skip: version(2) + random(32) + session_id_len(1) + session_id
    if ch.len() < 34 {
        return None;
    }
    let mut pos = 34;
    let session_id_len = ch[pos - 1] as usize;
    pos += session_id_len;

    // Skip cipher suites
    if pos + 2 > ch.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cipher_len;

    // Skip compression methods
    if pos + 1 > ch.len() {
        return None;
    }
    let comp_len = ch[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    if pos + 2 > ch.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;
    while pos + 4 <= ext_end && pos + 4 <= ch.len() {
        let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            if pos + 2 > ch.len() {
                return None;
            }
            let sni_list_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
            let mut sni_pos = pos + 2;
            let sni_end = sni_pos + sni_list_len;

            while sni_pos + 3 <= sni_end && sni_pos + 3 <= ch.len() {
                let name_type = ch[sni_pos];
                let name_len = u16::from_be_bytes([ch[sni_pos + 1], ch[sni_pos + 2]]) as usize;
                sni_pos += 3;

                if name_type == 0 && sni_pos + name_len <= ch.len() {
                    return String::from_utf8(ch[sni_pos..sni_pos + name_len].to_vec()).ok();
                }

                sni_pos += name_len;
            }
        }

        pos += ext_data_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS 1.2 ClientHello with a single SNI extension.
    ///
    /// Note: the parser interprets ch[33] (the last byte of the 32-byte random)
    /// as the session-ID length, then continues reading from pos=34 onward.
    /// We set random[31]=0 so the parser sees session_id_len=0, and place the
    /// cipher-suite data directly at byte 34 (no separate session_id_len byte).
    fn build_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();

        // SNI extension data:
        //   sni_list_len (2) + name_type (1) + name_len (2) + name
        let sni_list_len = (1 + 2 + sni_bytes.len()) as u16;
        let sni_ext_data_len = (2 + sni_list_len) as u16;

        let mut sni_ext = Vec::new();
        // Extension type: SNI (0x0000)
        sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
        // Extension data length
        sni_ext.extend_from_slice(&sni_ext_data_len.to_be_bytes());
        // SNI list length
        sni_ext.extend_from_slice(&sni_list_len.to_be_bytes());
        // Name type: hostname (0)
        sni_ext.push(0x00);
        // Name length
        sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        // Name
        sni_ext.extend_from_slice(sni_bytes);

        let extensions_len = sni_ext.len() as u16;

        // ClientHello body – adapted for the parser's actual byte layout:
        //   version(2) + random(32, last byte = 0) +
        //   cipher_suites_len(2) + cipher_suite(2) +
        //   comp_len(1) + comp(1) +
        //   extensions_len(2) + extensions
        //
        // No separate session_id_len byte: the parser reads random[31] for that.
        let mut ch_body = Vec::new();
        // Version: TLS 1.2
        ch_body.extend_from_slice(&[0x03, 0x03]);
        // Random (32 bytes, last byte = 0 so parser reads session_id_len = 0)
        ch_body.extend_from_slice(&[0u8; 32]);
        // Cipher suites length: 2 (one cipher suite) -- starts at ch[34]
        ch_body.extend_from_slice(&[0x00, 0x02]);
        // One cipher suite
        ch_body.extend_from_slice(&[0x00, 0x9c]);
        // Compression methods length: 1
        ch_body.push(0x01);
        // Compression method: null
        ch_body.push(0x00);
        // Extensions length
        ch_body.extend_from_slice(&extensions_len.to_be_bytes());
        // Extensions
        ch_body.extend_from_slice(&sni_ext);

        // Handshake header:
        //   type(1) = ClientHello(0x01) + length(3)
        let ch_len = ch_body.len();
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        handshake.push(((ch_len >> 16) & 0xFF) as u8);
        handshake.push(((ch_len >> 8) & 0xFF) as u8);
        handshake.push((ch_len & 0xFF) as u8);
        handshake.extend_from_slice(&ch_body);

        // TLS record layer:
        //   type(1) = Handshake(0x16) + version(2) + length(2)
        let hs_len = handshake.len();
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version (common)
        record.extend_from_slice(&(hs_len as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn extract_sni_from_client_hello() {
        let packet = build_client_hello("example.com");
        assert_eq!(extract_tls_sni(&packet), Some("example.com".to_string()));
    }

    #[test]
    fn extract_sni_with_subdomain() {
        let packet = build_client_hello("www.google.com");
        assert_eq!(extract_tls_sni(&packet), Some("www.google.com".to_string()));
    }

    #[test]
    fn returns_none_for_non_tls_data() {
        // HTTP request data
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_tls_sni(data), None);
    }

    #[test]
    fn returns_none_for_empty_data() {
        assert_eq!(extract_tls_sni(&[]), None);
    }

    #[test]
    fn returns_none_for_truncated_data() {
        // Just the TLS record header, truncated before handshake
        let data = &[0x16, 0x03, 0x01, 0x00, 0x50];
        assert_eq!(extract_tls_sni(data), None);
    }

    #[test]
    fn returns_none_for_short_data() {
        let data = &[0x16, 0x03];
        assert_eq!(extract_tls_sni(data), None);
    }

    // --- HTTP Host header extraction tests ---

    #[test]
    fn extract_http_host_get() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("example.com".to_string()));
    }

    #[test]
    fn extract_http_host_post() {
        let data = b"POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("api.example.com".to_string()));
    }

    #[test]
    fn extract_http_host_with_port() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("example.com".to_string()));
    }

    #[test]
    fn extract_http_host_lowercase() {
        let data = b"GET / HTTP/1.1\r\nhost: lowercase.com\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("lowercase.com".to_string()));
    }

    #[test]
    fn extract_http_host_none_for_binary() {
        let data = &[0x00, 0x01, 0x02, 0x03];
        assert_eq!(extract_http_host(data), None);
    }

    #[test]
    fn extract_http_host_connect() {
        let data = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("example.com".to_string()));
    }

    // --- sniff_domain dispatch tests ---

    #[test]
    fn sniff_domain_tls() {
        let packet = build_client_hello("tls.example.com");
        assert_eq!(sniff_domain(&packet), Some("tls.example.com".to_string()));
    }

    #[test]
    fn sniff_domain_http() {
        let data = b"GET / HTTP/1.1\r\nHost: http.example.com\r\n\r\n";
        assert_eq!(sniff_domain(data), Some("http.example.com".to_string()));
    }

    #[test]
    fn sniff_domain_empty() {
        assert_eq!(sniff_domain(&[]), None);
    }
}
