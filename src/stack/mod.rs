// Network stack abstraction.
//
// The "system" stack provides the TPROXY reply socket helper for the kernel
// datapath (redir/tproxy listeners). The "gvisor" (and "mixed") stack uses a
// real user-space TCP/IP stack (smoltcp, in `smol`) that terminates TCP/UDP
// from the TUN device — the faithful equivalent of mihomo's sing-tun gVisor
// stack.

pub mod smol;
pub mod system;
