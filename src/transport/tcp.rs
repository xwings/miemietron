use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Connect options for outbound TCP connections.
#[derive(Default)]
pub struct ConnectOpts {
    pub interface: Option<String>,
    pub routing_mark: Option<u32>,
    pub tfo: bool,
    pub mptcp: bool,
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
