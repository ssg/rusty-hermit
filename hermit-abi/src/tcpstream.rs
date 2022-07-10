//! `tcpstream` provide an interface to establish tcp socket client.

use crate::{IpAddress, NetworkError, Socket};

extern "Rust" {
	fn sys_tcp_stream_connect(
		ip: &[u8],
		port: u16,
		timeout: Option<u64>,
	) -> Result<Socket, NetworkError>;
	fn sys_tcp_stream_close(socket: Socket) -> Result<(), NetworkError>;
	fn sys_tcp_stream_read(socket: Socket, buffer: &mut [u8]) -> Result<usize, NetworkError>;
	fn sys_tcp_stream_write(socket: Socket, buffer: &[u8]) -> Result<usize, NetworkError>;
	fn sys_tcp_stream_set_read_timeout(
		socket: Socket,
		timeout: Option<u64>,
	) -> Result<(), NetworkError>;
	fn sys_tcp_stream_get_read_timeout(socket: Socket) -> Result<Option<u64>, NetworkError>;
	fn sys_tcp_stream_set_write_timeout(
		socket: Socket,
		timeout: Option<u64>,
	) -> Result<(), NetworkError>;
	fn sys_tcp_stream_get_write_timeout(socket: Socket) -> Result<Option<u64>, NetworkError>;
	fn sys_tcp_stream_peek(socket: Socket, buf: &mut [u8]) -> Result<usize, NetworkError>;
	fn sys_tcp_stream_set_tll(socket: Socket, ttl: u32) -> Result<(), NetworkError>;
	fn sys_tcp_stream_get_tll(socket: Socket) -> Result<u32, NetworkError>;
	fn sys_tcp_stream_shutdown(socket: Socket, how: i32) -> Result<(), NetworkError>;
	fn sys_tcp_stream_peer_addr(socket: Socket) -> Result<(IpAddress, u16), NetworkError>;
	fn sys_tcp_stream_set_non_blocking(
		socket: Socket,
		non_blocking: bool,
	) -> Result<(), NetworkError>;
}

/// Opens a TCP connection to a remote host.
#[inline(always)]
pub fn connect(ip: &[u8], port: u16, timeout: Option<u64>) -> Result<Socket, NetworkError> {
	unsafe { sys_tcp_stream_connect(ip, port, timeout) }
}

/// Close a TCP connection
#[inline(always)]
pub fn close(socket: Socket) -> Result<(), NetworkError> {
	unsafe { sys_tcp_stream_close(socket) }
}

#[inline(always)]
pub fn peek(socket: Socket, buf: &mut [u8]) -> Result<usize, NetworkError> {
	unsafe { sys_tcp_stream_peek(socket, buf) }
}

#[inline(always)]
pub fn peer_addr(socket: Socket) -> Result<(IpAddress, u16), NetworkError> {
	unsafe { sys_tcp_stream_peer_addr(socket) }
}

#[inline(always)]
pub fn read(socket: Socket, buffer: &mut [u8]) -> Result<usize, NetworkError> {
	unsafe { sys_tcp_stream_read(socket, buffer) }
}

#[inline(always)]
pub fn write(socket: Socket, buffer: &[u8]) -> Result<usize, NetworkError> {
	unsafe { sys_tcp_stream_write(socket, buffer) }
}

#[inline(always)]
pub fn set_read_timeout(socket: Socket, timeout: Option<u64>) -> Result<(), NetworkError> {
	unsafe { sys_tcp_stream_set_read_timeout(socket, timeout) }
}

#[inline(always)]
pub fn set_write_timeout(socket: Socket, timeout: Option<u64>) -> Result<(), NetworkError> {
	unsafe { sys_tcp_stream_set_write_timeout(socket, timeout) }
}

#[inline(always)]
pub fn get_read_timeout(socket: Socket) -> Result<Option<u64>, NetworkError> {
	unsafe { sys_tcp_stream_get_read_timeout(socket) }
}

#[inline(always)]
pub fn get_write_timeout(socket: Socket) -> Result<Option<u64>, NetworkError> {
	unsafe { sys_tcp_stream_get_write_timeout(socket) }
}

#[inline(always)]
pub fn set_nodelay(_: Socket, mode: bool) -> Result<(), NetworkError> {
	// smoltcp does not support Nagle's algorithm
	// => to enable Nagle's algorithm isn't possible
	if mode {
		Ok(())
	} else {
		Err(NetworkError::Unsupported)
	}
}

#[inline(always)]
pub fn nodelay(_: Socket) -> Result<bool, NetworkError> {
	// smoltcp does not support Nagle's algorithm
	// => return always true
	Ok(true)
}

#[inline(always)]
pub fn set_tll(socket: Socket, ttl: u32) -> Result<(), NetworkError> {
	unsafe { sys_tcp_stream_set_tll(socket, ttl) }
}

#[inline(always)]
pub fn get_tll(socket: Socket) -> Result<u32, NetworkError> {
	unsafe { sys_tcp_stream_get_tll(socket) }
}

#[inline(always)]
pub fn shutdown(socket: Socket, how: i32) -> Result<(), NetworkError> {
	unsafe { sys_tcp_stream_shutdown(socket, how) }
}

#[inline(always)]
pub fn set_non_blocking(socket: Socket, non_blocking: bool) -> Result<(), NetworkError> {
	unsafe { sys_tcp_stream_set_non_blocking(socket, non_blocking) }
}
