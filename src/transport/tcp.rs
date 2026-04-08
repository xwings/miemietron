use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpStream;

/// Connect options for outbound TCP connections.
#[derive(Default)]
pub struct ConnectOpts {
    pub interface: Option<String>,
    pub routing_mark: Option<u32>,
    pub tfo: bool,
    pub mptcp: bool,
    pub tcp_concurrent: bool,
    /// mihomo compat: keepalive settings from config.
    pub keep_alive_idle: Duration,
    pub keep_alive_interval: Duration,
    pub disable_keep_alive: bool,
}

/// Connect with Happy Eyeballs (RFC 8305): race multiple addresses with a
/// 250ms stagger. Returns the first successful connection.
pub async fn connect_concurrent(addrs: &[SocketAddr], opts: &ConnectOpts) -> Result<TcpStream> {
    if addrs.is_empty() {
        return Err(anyhow::anyhow!("no addresses to connect to"));
    }
    if addrs.len() == 1 || !opts.tcp_concurrent {
        return connect(addrs[0], opts).await;
    }

    use tokio::time::{sleep, Duration};

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<TcpStream>>(addrs.len());

    for (i, &addr) in addrs.iter().enumerate() {
        let tx = tx.clone();
        let opts_mark = opts.routing_mark;
        let opts_iface = opts.interface.clone();
        let opts_tfo = opts.tfo;

        tokio::spawn(async move {
            // Stagger: 250ms delay per attempt after the first
            if i > 0 {
                sleep(Duration::from_millis(250 * i as u64)).await;
            }
            let co = ConnectOpts {
                routing_mark: opts_mark,
                interface: opts_iface,
                tfo: opts_tfo,
                ..Default::default()
            };
            let result = connect(addr, &co).await;
            let _ = tx.send(result).await;
        });
    }

    drop(tx); // Drop our sender so the channel closes when all spawned tasks are done

    // Return the first successful result
    let mut last_err = anyhow::anyhow!("all connection attempts failed");
    while let Some(result) = rx.recv().await {
        match result {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Create a TCP connection with the given options.
pub async fn connect(addr: SocketAddr, opts: &ConnectOpts) -> Result<TcpStream> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // Set SO_MARK for TUN loop prevention
    if let Some(mark) = opts.routing_mark {
        #[cfg(target_os = "linux")]
        {
            socket.set_mark(mark)?;
        }
    }

    // Bind to specific interface
    if let Some(ref iface) = opts.interface {
        #[cfg(target_os = "linux")]
        {
            socket.bind_device(Some(iface.as_bytes()))?;
        }
    }

    // Set TCP Fast Open
    if opts.tfo {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            // TCP_FASTOPEN_CONNECT = 30
            let fd = socket.as_raw_fd();
            let val: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    30, // TCP_FASTOPEN_CONNECT
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
    }

    // mihomo compat: TCP keepalive (keepalive.SetNetDialer in dialer.go)
    if opts.disable_keep_alive {
        socket.set_keepalive(false)?;
    } else {
        socket.set_keepalive(true)?;
        if opts.keep_alive_idle.as_secs() > 0 {
            socket.set_tcp_keepalive(
                &socket2::TcpKeepalive::new()
                    .with_time(opts.keep_alive_idle)
                    .with_interval(opts.keep_alive_interval),
            )?;
        }
    }

    socket.set_nonblocking(true)?;

    let addr2: socket2::SockAddr = addr.into();
    match socket.connect(&addr2) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e.into()),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;

    // Wait for connection to complete
    stream.writable().await?;

    // Check for connection error
    if let Some(err) = stream.take_error()? {
        return Err(err.into());
    }

    Ok(stream)
}
