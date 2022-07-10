//! `tcplistener` provide an interface to establish tcp socket server.

use crate::{IpAddress, NetworkError, Socket};

extern "Rust" {
	fn sys_tcp_listener_accept(port: u16) -> Result<(Socket, IpAddress, u16), NetworkError>;
}

/// Wait for connection at specified address.
#[inline(always)]
pub fn accept(port: u16) -> Result<(Socket, IpAddress, u16), NetworkError> {
	unsafe { sys_tcp_listener_accept(port) }
}
