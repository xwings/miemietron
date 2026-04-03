use thiserror::Error;

#[derive(Error, Debug)]
pub enum MiemieError {
    #[error("config error: {0}")]
    Config(String),

    #[error("TUN error: {0}")]
    Tun(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("proxy error: {0}")]
    Proxy(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("rule error: {0}")]
    Rule(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("timeout")]
    Timeout,
}
