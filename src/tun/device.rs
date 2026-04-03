use anyhow::Result;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::TunConfig;

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x400454ca;

/// TUN device wrapper with async I/O support.
pub struct TunDevice {
    fd: RawFd,
    async_fd: tokio::io::unix::AsyncFd<RawFdWrapper>,
}

struct RawFdWrapper(RawFd);

impl AsRawFd for RawFdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl TunDevice {
    pub fn open(config: &TunConfig) -> Result<Self> {
        // Open /dev/net/tun
        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "failed to open /dev/net/tun: {}",
                io::Error::last_os_error()
            ));
        }

        // Set up interface
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = config.device.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                copy_len,
            );
            ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;
        }

        let ret = unsafe { libc::ioctl(fd, TUNSETIFF as _, &ifr) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow::anyhow!(
                "TUNSETIFF failed: {}",
                io::Error::last_os_error()
            ));
        }

        // Set MTU
        set_mtu(&config.device, config.mtu)?;

        // Bring interface up
        bring_up(&config.device)?;

        // Set IP address
        if let Some(addr_str) = config.inet4_address.first() {
            set_address(&config.device, addr_str)?;
        }

        let async_fd = tokio::io::unix::AsyncFd::new(RawFdWrapper(fd))?;

        Ok(Self { fd, async_fd })
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl AsyncRead for TunDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = match self.async_fd.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            let unfilled = buf.initialize_unfilled();
            let n = unsafe {
                libc::read(
                    self.fd,
                    unfilled.as_mut_ptr() as *mut libc::c_void,
                    unfilled.len(),
                )
            };

            if n >= 0 {
                buf.advance(n as usize);
                return Poll::Ready(Ok(()));
            }

            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Poll::Ready(Err(err));
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.async_fd.poll_write_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };

            if n >= 0 {
                return Poll::Ready(Ok(n as usize));
            }

            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Poll::Ready(Err(err));
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn set_mtu(dev: &str, mtu: u32) -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(anyhow::anyhow!("socket: {}", io::Error::last_os_error()));
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = dev.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            copy_len,
        );
        ifr.ifr_ifru.ifru_mtu = mtu as i32;
        let ret = libc::ioctl(sock, libc::SIOCSIFMTU as _, &ifr);
        libc::close(sock);
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "SIOCSIFMTU: {}",
                io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

fn bring_up(dev: &str) -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(anyhow::anyhow!("socket: {}", io::Error::last_os_error()));
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = dev.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            copy_len,
        );
        // Get current flags
        let ret = libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &ifr);
        if ret < 0 {
            libc::close(sock);
            return Err(anyhow::anyhow!(
                "SIOCGIFFLAGS: {}",
                io::Error::last_os_error()
            ));
        }
        ifr.ifr_ifru.ifru_flags |=
            libc::IFF_UP as libc::c_short | libc::IFF_RUNNING as libc::c_short;
        let ret = libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr);
        libc::close(sock);
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "SIOCSIFFLAGS: {}",
                io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

fn set_address(dev: &str, addr_cidr: &str) -> Result<()> {
    // Use ip command for simplicity - works on both full Linux and OpenWrt
    let output = std::process::Command::new("ip")
        .args(["addr", "add", addr_cidr, "dev", dev])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "already exists" errors
        if !stderr.contains("RTNETLINK answers: File exists") {
            return Err(anyhow::anyhow!("ip addr add failed: {}", stderr));
        }
    }
    Ok(())
}
