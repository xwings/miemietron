//! XHTTP (formerly SplitHTTP) client transport for VLESS.
//!
//! mihomo's non-REALITY `mode: auto` resolves to `packet-up`: a long-lived
//! GET carries downstream bytes while ordered POST requests carry upstream
//! bytes. `stream-one` and `stream-up` use streaming HTTP request bodies.
//! This module implements those three wire modes over HTTP/2, which is also
//! mihomo's default unless ALPN is explicitly restricted to HTTP/1.1 or h3.

use anyhow::{bail, Context, Result};
use base64::Engine;
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use futures_util::future::poll_fn;
use http::header::{
    ACCEPT, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, PRAGMA, USER_AGENT,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request};
use once_cell::sync::Lazy;
use rand::{Rng, RngCore};
use std::cmp::min;
use std::time::Duration;
use tokio::io::{
    split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf,
};
use tokio::time::{sleep_until, Instant};

use crate::config::proxy::XHttpOpts;

const DEFAULT_MAX_POST_BYTES: usize = 1_000_000;
const DEFAULT_POST_INTERVAL_MS: usize = 30;
const STREAM_BUFFER_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    StreamOne,
    StreamUp,
    PacketUp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    Path,
    Query,
    Cookie,
    Header,
    QueryInHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataPlacement {
    Body,
    Header,
    Cookie,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaddingMethod {
    RepeatX,
    Tokenish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NumberRange {
    min: usize,
    max: usize,
}

impl NumberRange {
    fn parse(value: Option<&str>, fallback: &str, field: &str) -> Result<Self> {
        let value = value.unwrap_or(fallback).trim();
        let mut parts = value.split('-').map(str::trim);
        let min = parts
            .next()
            .context("range must not be empty")?
            .parse::<usize>()
            .with_context(|| format!("invalid {field}: {value}"))?;
        let max = match parts.next() {
            Some(part) => part
                .parse::<usize>()
                .with_context(|| format!("invalid {field}: {value}"))?,
            None => min,
        };
        if parts.next().is_some() || max < min {
            bail!("invalid {field}: {value}");
        }
        Ok(Self { min, max })
    }

    fn random(self) -> usize {
        if self.min == self.max {
            self.min
        } else {
            rand::thread_rng().gen_range(self.min..=self.max)
        }
    }
}

/// Normalized XHTTP settings used by the transport.
#[derive(Debug, Clone)]
pub struct XHttpConfig {
    host: String,
    path: String,
    mode: Mode,
    headers: HeaderMap,
    no_grpc_header: bool,
    padding_bytes: NumberRange,
    padding_obfs_mode: bool,
    padding_key: String,
    padding_header: String,
    padding_placement: Placement,
    padding_method: PaddingMethod,
    uplink_method: Method,
    session_placement: Placement,
    session_key: String,
    session_table: Option<String>,
    session_length: NumberRange,
    seq_placement: Placement,
    seq_key: String,
    data_placement: DataPlacement,
    data_key: String,
    uplink_chunk_size: NumberRange,
    max_post_bytes: NumberRange,
    post_interval_ms: NumberRange,
}

impl XHttpConfig {
    /// Normalize mihomo-compatible config. `has_reality` only changes the
    /// effective value of `mode: auto`, matching mihomo `EffectiveMode`.
    pub fn from_options(
        opts: Option<&XHttpOpts>,
        fallback_host: &str,
        has_reality: bool,
    ) -> Result<Self> {
        let default = XHttpOpts::default();
        let opts = opts.unwrap_or(&default);

        if opts.download_settings.is_some() {
            bail!("VLESS XHTTP: download-settings is not implemented yet");
        }

        let normalized_mode = opts.mode.as_deref().unwrap_or("auto");
        let mode = match normalized_mode {
            "auto" if has_reality => Mode::StreamOne,
            "auto" => Mode::PacketUp,
            "stream-one" => Mode::StreamOne,
            "stream-up" => Mode::StreamUp,
            "packet-up" => Mode::PacketUp,
            other => bail!("VLESS XHTTP: mode {other} is not implemented"),
        };

        let session_placement = parse_meta_placement(
            opts.session_placement.as_deref().unwrap_or("path"),
            "session-placement",
        )?;
        let seq_placement = parse_meta_placement(
            opts.seq_placement.as_deref().unwrap_or("path"),
            "seq-placement",
        )?;

        let mut path = opts.path.as_deref().unwrap_or("/").to_string();
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        // Current mihomo Meta always normalizes XHTTP paths with a trailing
        // slash, independent of metadata placement.
        if !path.ends_with('/') {
            path.push('/');
        }

        let mut headers = HeaderMap::new();
        for (name, value) in &opts.headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("VLESS XHTTP: invalid header name {name:?}"))?;
            let value = HeaderValue::from_str(value)
                .with_context(|| format!("VLESS XHTTP: invalid value for header {name}"))?;
            headers.insert(name, value);
        }

        let padding_bytes = NumberRange::parse(
            opts.x_padding_bytes.as_deref(),
            "100-1000",
            "x-padding-bytes",
        )?;
        let padding_obfs_mode = opts.x_padding_obfs_mode.unwrap_or(false);
        let padding_placement = if padding_obfs_mode {
            parse_padding_placement(
                opts.x_padding_placement
                    .as_deref()
                    .unwrap_or("queryInHeader"),
            )?
        } else {
            Placement::QueryInHeader
        };
        let padding_method = match opts.x_padding_method.as_deref().unwrap_or("repeat-x") {
            "" | "repeat-x" => PaddingMethod::RepeatX,
            "tokenish" => PaddingMethod::Tokenish,
            other => bail!("VLESS XHTTP: unsupported x-padding-method {other}"),
        };

        let uplink_method = Method::from_bytes(
            opts.uplink_http_method
                .as_deref()
                .unwrap_or("POST")
                .as_bytes(),
        )
        .context("VLESS XHTTP: invalid uplink-http-method")?;
        if uplink_method == Method::GET {
            bail!("VLESS XHTTP: uplink-http-method must not be GET");
        }

        let data_placement = match opts.uplink_data_placement.as_deref().unwrap_or("body") {
            "body" => DataPlacement::Body,
            "header" => DataPlacement::Header,
            "cookie" => DataPlacement::Cookie,
            "auto" => DataPlacement::Auto,
            other => bail!("VLESS XHTTP: unsupported uplink-data-placement {other}"),
        };

        let max_post_bytes = NumberRange::parse(
            opts.sc_max_each_post_bytes.as_deref(),
            &DEFAULT_MAX_POST_BYTES.to_string(),
            "sc-max-each-post-bytes",
        )?;
        if max_post_bytes.max == 0 {
            bail!("VLESS XHTTP: sc-max-each-post-bytes must be greater than zero");
        }
        let post_interval_ms = NumberRange::parse(
            opts.sc_min_posts_interval_ms.as_deref(),
            &DEFAULT_POST_INTERVAL_MS.to_string(),
            "sc-min-posts-interval-ms",
        )?;
        if post_interval_ms.max == 0 {
            bail!("VLESS XHTTP: sc-min-posts-interval-ms must be greater than zero");
        }

        let chunk_fallback = match data_placement {
            DataPlacement::Cookie => "2048-3072".to_string(),
            DataPlacement::Header => "3072-4096".to_string(),
            DataPlacement::Body | DataPlacement::Auto => max_post_bytes.max.to_string(),
        };
        let mut uplink_chunk_size = NumberRange::parse(
            opts.uplink_chunk_size.as_deref(),
            &chunk_fallback,
            "uplink-chunk-size",
        )?;
        if uplink_chunk_size.max == 0 {
            uplink_chunk_size = NumberRange::parse(None, &chunk_fallback, "uplink-chunk-size")?;
        } else if uplink_chunk_size.min < 64 {
            uplink_chunk_size.min = 64;
            uplink_chunk_size.max = uplink_chunk_size.max.max(64);
        }

        let session_length =
            NumberRange::parse(opts.session_length.as_deref(), "16-32", "session-length")?;
        if session_length.min == 0 {
            bail!("VLESS XHTTP: session-length must be greater than zero");
        }

        let session_key = opts
            .session_key
            .clone()
            .unwrap_or_else(|| default_meta_key(session_placement, "X-Session", "x_session"));
        let seq_key = opts
            .seq_key
            .clone()
            .unwrap_or_else(|| default_meta_key(seq_placement, "X-Seq", "x_seq"));

        Ok(Self {
            host: opts
                .host
                .clone()
                .filter(|host| !host.is_empty())
                .unwrap_or_else(|| fallback_host.to_string()),
            path,
            mode,
            headers,
            no_grpc_header: opts.no_grpc_header.unwrap_or(false),
            padding_bytes,
            padding_obfs_mode,
            padding_key: opts
                .x_padding_key
                .clone()
                .unwrap_or_else(|| "x_padding".to_string()),
            padding_header: opts
                .x_padding_header
                .clone()
                .unwrap_or_else(|| "Referer".to_string()),
            padding_placement,
            padding_method,
            uplink_method,
            session_placement,
            session_key,
            session_table: opts.session_table.clone(),
            session_length,
            seq_placement,
            seq_key,
            data_placement,
            data_key: opts.uplink_data_key.clone().unwrap_or_default(),
            uplink_chunk_size,
            max_post_bytes,
            post_interval_ms,
        })
    }

    fn generate_session_id(&self) -> Result<String> {
        match self.session_table.as_deref() {
            None | Some("") => {
                let mut bytes = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut bytes);
                Ok(hex::encode(bytes))
            }
            Some("uuid") => Ok(uuid::Uuid::new_v4().to_string()),
            Some(table_name) => {
                let table = predefined_session_table(table_name).unwrap_or(table_name);
                if table.is_empty() || !table.is_ascii() {
                    bail!("VLESS XHTTP: session-table must contain ASCII characters");
                }
                let len = self.session_length.random();
                let bytes = table.as_bytes();
                let mut rng = rand::thread_rng();
                Ok((0..len)
                    .map(|_| bytes[rng.gen_range(0..bytes.len())] as char)
                    .collect())
            }
        }
    }

    fn base_headers(&self) -> HeaderMap {
        let mut headers = self.headers.clone();
        // mihomo's TryDefaultHeadersWith(..., "fetch") defaults to a Chrome-
        // shaped fetch request. User-supplied headers still take precedence.
        if !headers.contains_key(USER_AGENT) {
            headers.insert(
                USER_AGENT,
                HeaderValue::from_str(&DEFAULT_CHROME_HEADERS.ua).unwrap(),
            );
            headers.insert(
                "sec-ch-ua",
                HeaderValue::from_str(&DEFAULT_CHROME_HEADERS.ua_ch).unwrap(),
            );
            headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
            headers.insert(
                "sec-ch-ua-platform",
                HeaderValue::from_static("\"Windows\""),
            );
            headers.insert("dnt", HeaderValue::from_static("1"));
            headers.insert(
                "accept-language",
                HeaderValue::from_static("en-US,en;q=0.9"),
            );
            headers.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
            headers.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
            headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
            headers.insert("priority", HeaderValue::from_static("u=1, i"));
        }
        if !headers.contains_key(CACHE_CONTROL) {
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        }
        if !headers.contains_key(PRAGMA) {
            headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
        }
        if !headers.contains_key(ACCEPT) {
            headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
        }
        headers
    }

    fn stream_request(&self, method: Method, session: Option<&str>) -> Result<Request<()>> {
        let mut target = self.path.clone();
        let mut headers = self.base_headers();
        self.apply_padding(&mut target, &mut headers)?;
        if let Some(session) = session {
            apply_meta(
                &mut target,
                &mut headers,
                self.session_placement,
                &self.session_key,
                session,
            )?;
        }
        if method != Method::GET && !self.no_grpc_header {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
        }
        self.build_request(method, target, headers)
    }

    fn packet_request(
        &self,
        session: &str,
        seq: u64,
        payload: &[u8],
    ) -> Result<(Request<()>, Bytes)> {
        let mut target = self.path.clone();
        let mut headers = self.base_headers();
        let mut body = Bytes::new();

        match self.data_placement {
            DataPlacement::Body | DataPlacement::Auto => {
                body = Bytes::copy_from_slice(payload);
                headers.insert(
                    CONTENT_LENGTH,
                    HeaderValue::from_str(&payload.len().to_string())?,
                );
            }
            DataPlacement::Header => {
                append_payload_headers(
                    &mut headers,
                    &self.data_key,
                    payload,
                    self.uplink_chunk_size,
                )?;
                headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
            }
            DataPlacement::Cookie => {
                append_payload_cookies(
                    &mut headers,
                    &self.data_key,
                    payload,
                    self.uplink_chunk_size,
                )?;
                headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
            }
        }

        self.apply_padding(&mut target, &mut headers)?;
        apply_meta(
            &mut target,
            &mut headers,
            self.session_placement,
            &self.session_key,
            session,
        )?;
        apply_meta(
            &mut target,
            &mut headers,
            self.seq_placement,
            &self.seq_key,
            &seq.to_string(),
        )?;

        Ok((
            self.build_request(self.uplink_method.clone(), target, headers)?,
            body,
        ))
    }

    fn apply_padding(&self, target: &mut String, headers: &mut HeaderMap) -> Result<()> {
        let length = self.padding_bytes.random();
        let padding = generate_padding(self.padding_method, length);
        let (placement, key, header) = if self.padding_obfs_mode {
            (
                self.padding_placement,
                self.padding_key.as_str(),
                self.padding_header.as_str(),
            )
        } else {
            (Placement::QueryInHeader, "x_padding", "Referer")
        };

        match placement {
            Placement::Header => {
                let name = HeaderName::from_bytes(header.as_bytes())?;
                headers.insert(name, HeaderValue::from_str(&padding)?);
            }
            Placement::QueryInHeader => {
                let name = HeaderName::from_bytes(header.as_bytes())?;
                let referer = format!(
                    "https://{}{}?{}={}",
                    self.host,
                    self.path,
                    percent_encode(key),
                    percent_encode(&padding)
                );
                headers.insert(name, HeaderValue::from_str(&referer)?);
            }
            Placement::Cookie => append_cookie(headers, key, &padding)?,
            Placement::Query => append_query(target, key, &padding),
            Placement::Path => unreachable!("path is not a valid X-Padding placement"),
        }
        Ok(())
    }

    fn build_request(
        &self,
        method: Method,
        target: String,
        mut headers: HeaderMap,
    ) -> Result<Request<()>> {
        headers.insert(HOST, HeaderValue::from_str(&self.host)?);
        let mut request = Request::builder().method(method).uri(target).body(())?;
        *request.headers_mut() = headers;
        Ok(request)
    }
}

/// Establish a mihomo-compatible XHTTP stream over an existing HTTP/2-capable
/// transport. The caller must perform TLS first with ALPN forced to `h2`.
pub async fn connect_h2<S>(stream: S, config: XHttpConfig) -> Result<DuplexStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = h2::client::handshake(stream)
        .await
        .context("XHTTP HTTP/2 handshake failed")?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!("XHTTP HTTP/2 connection ended: {error}");
        }
    });

    let (client_stream, worker_stream) = tokio::io::duplex(STREAM_BUFFER_BYTES);
    let (worker_read, worker_write) = split(worker_stream);

    match config.mode {
        Mode::StreamOne => {
            wait_ready(&mut sender).await?;
            let request = config.stream_request(config.uplink_method.clone(), None)?;
            let (response, upload) = sender.send_request(request, false)?;
            spawn_stream_upload(worker_read, upload);
            spawn_download(worker_write, response, "stream-one");
        }
        Mode::StreamUp => {
            let session = config.generate_session_id()?;

            wait_ready(&mut sender).await?;
            let download_request = config.stream_request(Method::GET, Some(&session))?;
            let (download_response, _) = sender.send_request(download_request, true)?;

            // Queue the GET before the upload request, matching mihomo's
            // session-creation ordering while remaining non-blocking on the
            // long-lived download response headers.
            wait_ready(&mut sender).await?;
            let upload_request =
                config.stream_request(config.uplink_method.clone(), Some(&session))?;
            let (upload_response, upload) = sender.send_request(upload_request, false)?;
            spawn_stream_upload(worker_read, upload);
            spawn_response_drain(upload_response, "stream-up upload");
            spawn_download(worker_write, download_response, "stream-up download");
        }
        Mode::PacketUp => {
            let session = config.generate_session_id()?;
            wait_ready(&mut sender).await?;
            let download_request = config.stream_request(Method::GET, Some(&session))?;
            let (download_response, _) = sender.send_request(download_request, true)?;

            spawn_packet_upload(worker_read, sender, config, session);
            spawn_download(worker_write, download_response, "packet-up download");
        }
    }

    Ok(client_stream)
}

fn spawn_stream_upload(mut reader: ReadHalf<DuplexStream>, mut upload: h2::SendStream<Bytes>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    let _ = upload.send_data(Bytes::new(), true);
                    break;
                }
                Ok(n) => {
                    if let Err(error) = send_body_chunk(&mut upload, &buf[..n], false).await {
                        tracing::debug!("XHTTP streaming upload failed: {error:#}");
                        break;
                    }
                }
                Err(error) => {
                    tracing::debug!("XHTTP streaming upload reader failed: {error}");
                    break;
                }
            }
        }
    });
}

fn spawn_packet_upload(
    mut reader: ReadHalf<DuplexStream>,
    mut sender: h2::client::SendRequest<Bytes>,
    config: XHttpConfig,
    session: String,
) {
    tokio::spawn(async move {
        let mut input = vec![0u8; 32 * 1024];
        // mihomo samples sc-max-each-post-bytes once per packet-up connection.
        let max_post_bytes = config.max_post_bytes.random();
        let mut buffered = Vec::with_capacity(min(max_post_bytes, 64 * 1024));
        let mut seq = 0u64;

        loop {
            if buffered.is_empty() {
                match reader.read(&mut input).await {
                    Ok(0) => break,
                    Ok(n) => buffered.extend_from_slice(&input[..n]),
                    Err(error) => {
                        tracing::debug!("XHTTP packet-up reader failed: {error}");
                        break;
                    }
                }
            }

            let deadline =
                Instant::now() + Duration::from_millis(config.post_interval_ms.random() as u64);
            while buffered.len() < max_post_bytes {
                let room = max_post_bytes.saturating_sub(buffered.len());
                if room == 0 {
                    break;
                }
                let read_len = min(room, input.len());
                tokio::select! {
                    result = reader.read(&mut input[..read_len]) => {
                        match result {
                            Ok(0) => break,
                            Ok(n) => buffered.extend_from_slice(&input[..n]),
                            Err(error) => {
                                tracing::debug!("XHTTP packet-up reader failed: {error}");
                                return;
                            }
                        }
                    }
                    _ = sleep_until(deadline) => break,
                }
            }

            let post_size = min(buffered.len(), max_post_bytes.max(1));
            let payload: Vec<u8> = buffered.drain(..post_size).collect();
            if let Err(error) = send_packet(&mut sender, &config, &session, seq, &payload).await {
                tracing::debug!("XHTTP packet-up POST failed: {error:#}");
                return;
            }
            seq += 1;
        }
    });
}

fn spawn_download(
    mut writer: WriteHalf<DuplexStream>,
    response: h2::client::ResponseFuture,
    label: &'static str,
) {
    tokio::spawn(async move {
        let result: Result<()> = async {
            let response = response.await?;
            if !response.status().is_success() {
                bail!("XHTTP {label} returned HTTP {}", response.status());
            }
            let mut body = response.into_body();
            while let Some(chunk) = body.data().await {
                let chunk = chunk?;
                body.flow_control().release_capacity(chunk.len())?;
                writer.write_all(&chunk).await?;
            }
            writer.shutdown().await?;
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::debug!("XHTTP {label} failed: {error:#}");
        }
    });
}

fn spawn_response_drain(response: h2::client::ResponseFuture, label: &'static str) {
    tokio::spawn(async move {
        let result: Result<()> = async {
            let response = response.await?;
            if !response.status().is_success() {
                bail!("XHTTP {label} returned HTTP {}", response.status());
            }
            let mut body = response.into_body();
            while let Some(chunk) = body.data().await {
                let chunk = chunk?;
                body.flow_control().release_capacity(chunk.len())?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::debug!("XHTTP {label} failed: {error:#}");
        }
    });
}

async fn send_packet(
    sender: &mut h2::client::SendRequest<Bytes>,
    config: &XHttpConfig,
    session: &str,
    seq: u64,
    payload: &[u8],
) -> Result<()> {
    let (request, body) = config.packet_request(session, seq, payload)?;
    wait_ready(sender).await?;
    let end_stream = body.is_empty();
    let (response, mut upload) = sender.send_request(request, end_stream)?;
    if !body.is_empty() {
        send_body_chunk(&mut upload, &body, true).await?;
    }

    let response = response.await?;
    if response.status() != http::StatusCode::OK {
        bail!("XHTTP packet-up returned HTTP {}", response.status());
    }
    let mut response_body = response.into_body();
    while let Some(chunk) = response_body.data().await {
        let chunk = chunk?;
        response_body.flow_control().release_capacity(chunk.len())?;
    }
    Ok(())
}

async fn wait_ready(sender: &mut h2::client::SendRequest<Bytes>) -> Result<()> {
    poll_fn(|cx| sender.poll_ready(cx)).await?;
    Ok(())
}

async fn send_body_chunk(
    stream: &mut h2::SendStream<Bytes>,
    data: &[u8],
    end_stream: bool,
) -> Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        stream.reserve_capacity(data.len() - offset);
        let capacity = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .context("XHTTP request stream closed")??;
        if capacity == 0 {
            continue;
        }
        let count = min(capacity, data.len() - offset);
        let last = offset + count == data.len();
        stream.send_data(
            Bytes::copy_from_slice(&data[offset..offset + count]),
            end_stream && last,
        )?;
        offset += count;
    }
    if data.is_empty() && end_stream {
        stream.send_data(Bytes::new(), true)?;
    }
    Ok(())
}

fn parse_meta_placement(value: &str, field: &str) -> Result<Placement> {
    match value {
        "path" => Ok(Placement::Path),
        "query" => Ok(Placement::Query),
        "cookie" => Ok(Placement::Cookie),
        "header" => Ok(Placement::Header),
        other => bail!("VLESS XHTTP: unsupported {field} {other}"),
    }
}

fn parse_padding_placement(value: &str) -> Result<Placement> {
    match value {
        "queryInHeader" => Ok(Placement::QueryInHeader),
        "query" => Ok(Placement::Query),
        "cookie" => Ok(Placement::Cookie),
        "header" => Ok(Placement::Header),
        other => bail!("VLESS XHTTP: unsupported x-padding-placement {other}"),
    }
}

fn default_meta_key(placement: Placement, header: &str, scalar: &str) -> String {
    match placement {
        Placement::Header => header.to_string(),
        Placement::Cookie | Placement::Query => scalar.to_string(),
        Placement::Path | Placement::QueryInHeader => String::new(),
    }
}

fn apply_meta(
    target: &mut String,
    headers: &mut HeaderMap,
    placement: Placement,
    key: &str,
    value: &str,
) -> Result<()> {
    match placement {
        Placement::Path => append_path(target, value),
        Placement::Query => append_query(target, key, value),
        Placement::Cookie => append_cookie(headers, key, value)?,
        Placement::Header => {
            let name = HeaderName::from_bytes(key.as_bytes())?;
            headers.insert(name, HeaderValue::from_str(value)?);
        }
        Placement::QueryInHeader => unreachable!("queryInHeader is not metadata placement"),
    }
    Ok(())
}

fn append_path(target: &mut String, value: &str) {
    if !target.ends_with('/') {
        target.push('/');
    }
    target.push_str(value);
}

fn append_query(target: &mut String, key: &str, value: &str) {
    target.push(if target.contains('?') { '&' } else { '?' });
    target.push_str(&percent_encode(key));
    target.push('=');
    target.push_str(&percent_encode(value));
}

fn percent_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn append_cookie(headers: &mut HeaderMap, key: &str, value: &str) -> Result<()> {
    let cookie = format!("{key}={value}");
    if let Some(existing) = headers.get(COOKIE) {
        let combined = format!("{}; {cookie}", existing.to_str()?);
        headers.insert(COOKIE, HeaderValue::from_str(&combined)?);
    } else {
        headers.insert(COOKIE, HeaderValue::from_str(&cookie)?);
    }
    Ok(())
}

fn append_payload_headers(
    headers: &mut HeaderMap,
    key: &str,
    payload: &[u8],
    chunk_size: NumberRange,
) -> Result<()> {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    let mut offset = 0;
    let mut index = 0;
    while offset < encoded.len() {
        let count = min(chunk_size.random(), encoded.len() - offset);
        let name = HeaderName::from_bytes(format!("{key}-{index}").as_bytes())?;
        headers.insert(
            name,
            HeaderValue::from_str(&encoded[offset..offset + count])?,
        );
        offset += count;
        index += 1;
    }
    Ok(())
}

fn append_payload_cookies(
    headers: &mut HeaderMap,
    key: &str,
    payload: &[u8],
    chunk_size: NumberRange,
) -> Result<()> {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    let mut offset = 0;
    let mut index = 0;
    while offset < encoded.len() {
        let count = min(chunk_size.random(), encoded.len() - offset);
        append_cookie(
            headers,
            &format!("{key}_{index}"),
            &encoded[offset..offset + count],
        )?;
        offset += count;
        index += 1;
    }
    Ok(())
}

fn generate_padding(method: PaddingMethod, target_bytes: usize) -> String {
    if target_bytes == 0 {
        return String::new();
    }
    match method {
        PaddingMethod::RepeatX => "X".repeat(target_bytes),
        PaddingMethod::Tokenish => {
            const TABLE: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            let mut rng = rand::thread_rng();
            let initial = ((target_bytes as f64) / 0.8).ceil().max(1.0) as usize;
            let mut value: String = (0..initial)
                .map(|_| TABLE[rng.gen_range(0..TABLE.len())] as char)
                .collect();
            let mut adjust = 'X';
            for _ in 0..150 {
                let encoded = hpack_huffman_bytes(&value);
                if encoded.abs_diff(target_bytes) <= 2 {
                    break;
                }
                if encoded < target_bytes {
                    value.push(adjust);
                    adjust = if adjust == 'X' { 'Z' } else { 'X' };
                } else if value.len() > 1 {
                    value.pop();
                } else {
                    break;
                }
            }
            value
        }
    }
}

fn hpack_huffman_bytes(value: &str) -> usize {
    let bits: usize = value.bytes().map(hpack_code_bits).sum();
    bits.div_ceil(8)
}

fn hpack_code_bits(byte: u8) -> usize {
    match byte {
        b'0'..=b'2' => 5,
        b'3'..=b'9' => 6,
        b'A' => 6,
        b'B'..=b'W' | b'Y' => 7,
        b'X' | b'Z' => 8,
        b'a' | b'c' | b'e' | b'i' | b'o' | b's' | b't' => 5,
        b'b' | b'd' | b'f' | b'g' | b'h' | b'l' | b'm' | b'n' | b'p' | b'r' | b'u' => 6,
        b'j' | b'k' | b'q' | b'v'..=b'z' => 7,
        _ => 8,
    }
}

fn predefined_session_table(name: &str) -> Option<&'static str> {
    match name {
        "ALPHABET" => Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "Alphabet" => Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
        "BASE36" => Some("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "Base62" => Some("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
        "HEX" => Some("0123456789ABCDEF"),
        "alphabet" => Some("abcdefghijklmnopqrstuvwxyz"),
        "base36" => Some("0123456789abcdefghijklmnopqrstuvwxyz"),
        "hex" => Some("0123456789abcdef"),
        "number" => Some("0123456789"),
        _ => None,
    }
}

struct ChromeHeaders {
    ua: String,
    ua_ch: String,
}

static DEFAULT_CHROME_HEADERS: Lazy<ChromeHeaders> = Lazy::new(|| {
    // Port of mihomo transport/xhttp/browser.go. The version is anchored to
    // Chrome's release cadence and randomized once per process.
    let start = Utc.with_ymd_and_hms(2026, 1, 13, 0, 0, 0).unwrap();
    let current_days = Utc::now().timestamp() / 86_400;
    let start_days = start.timestamp() / 86_400;
    let deviation = (rand::thread_rng().gen::<f64>().powi(2) * 105.0).floor() as i64;
    let version = 144 + ((current_days - start_days - 35 - deviation) / 35) as i32;
    let ua = format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36"
    );

    let grease_chars = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
    let grease_versions = ["8", "99", "24"];
    let seed = version as usize;
    let invalid_brand = format!(
        "\"Not{}A{}Brand\";v=\"{}\"",
        grease_chars[seed % grease_chars.len()],
        grease_chars[(seed + 1) % grease_chars.len()],
        grease_versions[seed % grease_versions.len()]
    );
    let brands = [
        invalid_brand,
        format!("\"Chromium\";v=\"{version}\""),
        format!("\"Google Chrome\";v=\"{version}\""),
    ];
    let shuffles = [
        [0usize, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let shuffle = shuffles[seed % shuffles.len()];
    let mut ordered = [String::new(), String::new(), String::new()];
    for (index, destination) in shuffle.into_iter().enumerate() {
        ordered[destination] = brands[index].clone();
    }

    ChromeHeaders {
        ua,
        ua_ch: ordered.join(", "),
    }
});

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::REFERER;
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::timeout;

    fn generic_config() -> XHttpConfig {
        XHttpConfig::from_options(
            Some(&XHttpOpts {
                host: Some("edge.example.com".to_string()),
                path: Some("/tunnel".to_string()),
                mode: Some("auto".to_string()),
                x_padding_bytes: Some("100".to_string()),
                sc_min_posts_interval_ms: Some("1".to_string()),
                ..XHttpOpts::default()
            }),
            "proxy.example.com",
            false,
        )
        .unwrap()
    }

    #[test]
    fn auto_without_reality_is_packet_up() {
        let config = generic_config();
        assert_eq!(config.mode, Mode::PacketUp);
        assert_eq!(config.path, "/tunnel/");
    }

    #[test]
    fn packet_request_matches_mihomo_default_layout() {
        let config = generic_config();
        let (request, body) = config
            .packet_request("0123456789abcdef", 7, b"vless bytes")
            .unwrap();
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri().path(), "/tunnel/0123456789abcdef/7");
        assert_eq!(body.as_ref(), b"vless bytes");
        assert_eq!(request.headers()[HOST], "edge.example.com");
        let referer = request.headers()[REFERER].to_str().unwrap();
        assert!(referer.starts_with("https://edge.example.com/tunnel/?x_padding="));
        assert_eq!(referer.rsplit('=').next().unwrap().len(), 100);
    }

    #[test]
    fn tokenish_padding_hits_hpack_target() {
        for target in [100usize, 257, 1000] {
            let padding = generate_padding(PaddingMethod::Tokenish, target);
            assert!(hpack_huffman_bytes(&padding).abs_diff(target) <= 2);
        }
    }

    #[tokio::test]
    async fn packet_up_round_trip_over_h2() {
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let (request_tx, mut request_rx) = mpsc::unbounded_channel();
        let (download_tx, download_rx) = oneshot::channel::<h2::SendStream<Bytes>>();

        tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let mut download_tx = Some(download_tx);
            while let Some(result) = connection.accept().await {
                let (request, mut respond) = result.unwrap();
                let method = request.method().clone();
                let path = request.uri().path().to_string();
                let referer = request
                    .headers()
                    .get(REFERER)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                if method == Method::GET {
                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let send = respond.send_response(response, false).unwrap();
                    download_tx.take().unwrap().send(send).unwrap();
                } else {
                    let request_tx = request_tx.clone();
                    tokio::spawn(async move {
                        let mut body = request.into_body();
                        let mut payload = Vec::new();
                        while let Some(chunk) = body.data().await {
                            let chunk = chunk.unwrap();
                            body.flow_control().release_capacity(chunk.len()).unwrap();
                            payload.extend_from_slice(&chunk);
                        }
                        request_tx.send((path, referer, payload)).unwrap();
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        respond.send_response(response, true).unwrap();
                    });
                }
            }
        });

        let mut stream = timeout(
            Duration::from_secs(2),
            connect_h2(client_io, generic_config()),
        )
        .await
        .expect("XHTTP connect timed out")
        .unwrap();
        timeout(
            Duration::from_secs(2),
            stream.write_all(b"vless request and payload"),
        )
        .await
        .expect("XHTTP write timed out")
        .unwrap();

        let (path, referer, payload) = timeout(Duration::from_secs(2), request_rx.recv())
            .await
            .expect("packet-up POST timed out")
            .unwrap();
        assert!(path.starts_with("/tunnel/"));
        assert!(path.ends_with("/0"));
        assert!(referer.contains("?x_padding="));
        assert_eq!(payload, b"vless request and payload");

        let mut download = timeout(Duration::from_secs(2), download_rx)
            .await
            .expect("download GET timed out")
            .unwrap();
        download
            .send_data(Bytes::from_static(b"\x00\x00reply"), true)
            .unwrap();
        let mut response = [0u8; 7];
        timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .expect("XHTTP download timed out")
            .unwrap();
        assert_eq!(&response, b"\x00\x00reply");
    }
}
