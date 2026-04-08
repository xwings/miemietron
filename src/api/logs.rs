use axum::{
    extract::{ws, FromRequestParts, Request, State},
    response::{IntoResponse, Response},
};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing_subscriber::Layer;

use super::ApiState;

/// A single log entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LogEntry {
    #[serde(rename = "type")]
    pub level: String,
    pub payload: String,
}

/// Shared log channel for broadcasting log entries.
/// Also keeps a ring buffer of recent entries for non-WS clients.
#[derive(Clone)]
pub struct LogBroadcast {
    sender: broadcast::Sender<LogEntry>,
    recent: Arc<parking_lot::RwLock<VecDeque<LogEntry>>>,
    max_recent: usize,
}

impl LogBroadcast {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            recent: Arc::new(parking_lot::RwLock::new(VecDeque::with_capacity(capacity))),
            max_recent: capacity,
        }
    }

    pub fn send(&self, level: &str, message: &str) {
        let entry = LogEntry {
            level: level.to_string(),
            payload: message.to_string(),
        };
        // Store in recent buffer
        {
            let mut recent = self.recent.write();
            if recent.len() >= self.max_recent {
                recent.pop_front();
            }
            recent.push_back(entry.clone());
        }
        let _ = self.sender.send(entry);
    }

    #[allow(dead_code)]
    pub fn info(&self, msg: &str) {
        self.send("info", msg);
    }

    #[allow(dead_code)]
    pub fn warning(&self, msg: &str) {
        self.send("warning", msg);
    }

    #[allow(dead_code)]
    pub fn error(&self, msg: &str) {
        self.send("error", msg);
    }

    #[allow(dead_code)]
    pub fn debug(&self, msg: &str) {
        self.send("debug", msg);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        self.sender.subscribe()
    }

    /// Get the last N log entries.
    #[allow(dead_code)]
    pub fn recent_entries(&self, max: usize) -> Vec<LogEntry> {
        let recent = self.recent.read();
        recent.iter().rev().take(max).rev().cloned().collect()
    }
}

static LOG_BROADCAST: once_cell::sync::Lazy<Arc<LogBroadcast>> =
    once_cell::sync::Lazy::new(|| Arc::new(LogBroadcast::new(256)));

pub fn global_log_broadcast() -> Arc<LogBroadcast> {
    LOG_BROADCAST.clone()
}

/// A `tracing_subscriber::Layer` that sends every tracing event to the
/// global `LogBroadcast` channel, making logs available via the REST API
/// and WebSocket /logs endpoint.
pub struct BroadcastLayer {
    broadcast: Arc<LogBroadcast>,
}

impl BroadcastLayer {
    pub fn new(broadcast: Arc<LogBroadcast>) -> Self {
        Self { broadcast }
    }
}

impl<S> Layer<S> for BroadcastLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let level = match *event.metadata().level() {
            tracing::Level::ERROR => "error",
            tracing::Level::WARN => "warning",
            tracing::Level::INFO => "info",
            tracing::Level::DEBUG => "debug",
            tracing::Level::TRACE => "debug",
        };

        // Extract the message from the event fields
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        let message = if visitor.0.is_empty() {
            event.metadata().name().to_string()
        } else {
            visitor.0
        };

        self.broadcast.send(level, &message);
    }
}

/// Visitor that extracts the `message` field from a tracing event.
struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        } else if self.0.is_empty() {
            self.0 = format!("{}={:?}", field.name(), value);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        } else if self.0.is_empty() {
            self.0 = format!("{}={}", field.name(), value);
        }
    }
}

/// GET /logs - handles both WebSocket and plain HTTP requests.
///
/// Checks for WebSocket upgrade headers manually and dispatches accordingly.
/// - WebSocket: streams log entries as JSON objects `{"type":"info","payload":"..."}`
/// - HTTP GET: returns the last 100 log entries as a JSON array
pub async fn get_logs(State(state): State<ApiState>, request: Request) -> Response {
    // Extract query parameters from the URI before consuming the request
    let query_string = request.uri().query().unwrap_or("").to_string();
    let min_level = extract_level_param(&query_string);

    // Check if this is a WebSocket upgrade request
    let is_ws = request
        .headers()
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if is_ws {
        // Try WebSocket upgrade via FromRequestParts
        let (mut parts, _body) = request.into_parts();
        match axum::extract::WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
            Ok(ws) => ws.on_upgrade(move |socket| handle_log_ws(socket, min_level, state)),
            Err(e) => e.into_response(),
        }
    } else {
        // Plain HTTP: stream log entries as NDJSON (newline-delimited JSON),
        // matching mihomo's Go behavior which streams individual JSON objects
        // with a newline after each, flushing after each write.
        let broadcast = global_log_broadcast();
        let rx = broadcast.subscribe();

        let stream = futures_util::stream::unfold(rx, move |mut rx| {
            let min_level = min_level.clone();
            async move {
                loop {
                    match rx.recv().await {
                        Ok(entry) => {
                            if !level_passes(&entry.level, &min_level) {
                                continue;
                            }
                            if let Ok(json) = serde_json::to_string(&entry) {
                                return Some((
                                    Ok::<_, std::io::Error>(bytes::Bytes::from(format!(
                                        "{json}\n"
                                    ))),
                                    rx,
                                ));
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                }
            }
        });

        let body = axum::body::Body::from_stream(stream);
        Response::builder()
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(body)
            .unwrap()
            .into_response()
    }
}

fn extract_level_param(query: &str) -> String {
    for param in query.split('&') {
        if let Some(value) = param.strip_prefix("level=") {
            return value.to_string();
        }
    }
    "info".to_string()
}

async fn handle_log_ws(mut socket: ws::WebSocket, min_level: String, _state: ApiState) {
    let broadcast = global_log_broadcast();
    let mut rx = broadcast.subscribe();

    loop {
        match rx.recv().await {
            Ok(entry) => {
                if !level_passes(&entry.level, &min_level) {
                    continue;
                }
                let msg = match serde_json::to_string(&entry) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if socket.send(ws::Message::Text(msg.into())).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {
                // Slow consumer, skip missed messages
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// Check if a log level passes the minimum level filter.
fn level_passes(level: &str, min_level: &str) -> bool {
    let level_num = level_to_num(level);
    let min_num = level_to_num(min_level);
    level_num <= min_num
}

fn level_to_num(level: &str) -> u8 {
    match level.to_lowercase().as_str() {
        "silent" => 0,
        "error" => 1,
        "warning" | "warn" => 2,
        "info" => 3,
        "debug" => 4,
        _ => 3,
    }
}
