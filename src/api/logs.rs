use axum::http::StatusCode;
use std::sync::Arc;
use tokio::sync::broadcast;

/// A single log entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LogEntry {
    #[serde(rename = "type")]
    pub level: String,
    pub payload: String,
}

/// Shared log channel for broadcasting log entries.
#[derive(Clone)]
pub struct LogBroadcast {
    sender: broadcast::Sender<LogEntry>,
}

impl LogBroadcast {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn send(&self, level: &str, message: &str) {
        let _ = self.sender.send(LogEntry {
            level: level.to_string(),
            payload: message.to_string(),
        });
    }

    pub fn info(&self, msg: &str) {
        self.send("info", msg);
    }

    pub fn warning(&self, msg: &str) {
        self.send("warning", msg);
    }

    pub fn error(&self, msg: &str) {
        self.send("error", msg);
    }

    pub fn debug(&self, msg: &str) {
        self.send("debug", msg);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        self.sender.subscribe()
    }
}

static LOG_BROADCAST: once_cell::sync::Lazy<Arc<LogBroadcast>> =
    once_cell::sync::Lazy::new(|| Arc::new(LogBroadcast::new(256)));

pub fn global_log_broadcast() -> Arc<LogBroadcast> {
    LOG_BROADCAST.clone()
}

/// GET /logs - returns 200 OK. WebSocket streaming to be added via separate route.
pub async fn get_logs() -> StatusCode {
    StatusCode::OK
}
