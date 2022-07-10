pub mod device;
mod executor;
mod mutex;
mod waker;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::_rdtsc;
use std::collections::HashMap;
use std::ops::DerefMut;
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{Context, Poll};
use std::u16;

#[cfg(target_arch = "aarch64")]
use aarch64::regs::*;
use futures_lite::future;
use hermit_abi::NetworkError;
use lazy_static::lazy_static;
use smoltcp::iface::{self, SocketHandle};
use smoltcp::phy::Device;
#[cfg(feature = "trace")]
use smoltcp::phy::Tracer;
#[cfg(feature = "dhcpv4")]
use smoltcp::socket::{Dhcpv4Event, Dhcpv4Socket};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer, TcpState};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::IpAddress;
#[cfg(feature = "dhcpv4")]
use smoltcp::wire::{IpCidr, Ipv4Address, Ipv4Cidr};
#[cfg(target_arch = "aarch64")]
use tock_registers::interfaces::Readable;

use crate::net::device::HermitNet;
use crate::net::executor::{block_on, block_with_timeout_on, poll_on, spawn};
use crate::net::mutex::Mutex;
use crate::net::waker::WakerRegistration;

/// Type of a socket
#[derive(Debug, Clone, Copy)]
pub(crate) enum SocketType {
	/// TCP socket
	Tcp,
	/// UDP socket
	Udp,
}

impl Default for SocketType {
	fn default() -> Self {
		SocketType::Tcp
	}
}

/// used to modify and query data from OS Sockets
#[derive(Debug, Clone, Copy)]
pub(crate) struct SocketInfo {
	pub socket_type: SocketType,
	pub non_blocking: bool,
}

impl SocketInfo {
	pub fn new(socket_type: SocketType, non_blocking: bool) -> Self {
		Self {
			socket_type,
			non_blocking,
		}
	}
}

impl Default for SocketInfo {
	fn default() -> Self {
		Self {
			socket_type: SocketType::default(),
			non_blocking: false,
		}
	}
}

pub(crate) enum NetworkState {
	Missing,
	InitializationFailed,
	Initialized(NetworkInterface<HermitNet>),
}

impl NetworkState {
	fn as_nic_mut(&mut self) -> Result<&mut NetworkInterface<HermitNet>, &'static str> {
		match self {
			NetworkState::Initialized(nic) => Ok(nic),
			_ => Err("Network is not initialized!"),
		}
	}
}

lazy_static! {
	static ref NIC: Mutex<NetworkState> = Mutex::new(NetworkState::Missing);
	static ref SOCKET_MAP: Mutex<HashMap<Handle, SocketInfo>> = Mutex::new(HashMap::new());
}

extern "C" {
	fn sys_yield();
	fn sys_spawn(
		id: *mut Tid,
		func: extern "C" fn(usize),
		arg: usize,
		prio: u8,
		selector: isize,
	) -> i32;
	fn sys_netwait();
}

pub type Handle = SocketHandle;
pub type Tid = u32;

/// Default keep alive interval in milliseconds
const DEFAULT_KEEP_ALIVE_INTERVAL: u64 = 75000;

static LOCAL_ENDPOINT: AtomicU16 = AtomicU16::new(0);

pub(crate) struct NetworkInterface<T: for<'a> Device<'a>> {
	#[cfg(feature = "trace")]
	pub iface: smoltcp::iface::Interface<'static, Tracer<T>>,
	#[cfg(not(feature = "trace"))]
	pub iface: smoltcp::iface::Interface<'static, T>,
	#[cfg(feature = "dhcpv4")]
	dhcp_handle: SocketHandle,
	waker: WakerRegistration,
}

impl<T> NetworkInterface<T>
where
	T: for<'a> Device<'a>,
{
	pub(crate) fn create_handle(&mut self) -> Result<Handle, ()> {
		let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; 65535]);
		let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; 65535]);
		let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);
		let tcp_handle = self.iface.add_socket(tcp_socket);

		SOCKET_MAP
			.lock()
			.insert(tcp_handle, SocketInfo::new(SocketType::Tcp, false));

		Ok(tcp_handle)
	}

	pub(crate) fn wake(&mut self) {
		self.waker.wake()
	}

	pub(crate) fn poll_common(&mut self, timestamp: Instant) {
		while self.iface.poll(timestamp).unwrap_or(true) {
			// just to make progress
		}
		#[cfg(feature = "dhcpv4")]
		match self
			.iface
			.get_socket::<Dhcpv4Socket>(self.dhcp_handle)
			.poll()
		{
			None => {}
			Some(Dhcpv4Event::Configured(config)) => {
				info!("DHCP config acquired!");
				info!("IP address:      {}", config.address);
				self.iface.update_ip_addrs(|addrs| {
					let dest = addrs.iter_mut().next().unwrap();
					*dest = IpCidr::Ipv4(config.address);
				});
				if let Some(router) = config.router {
					info!("Default gateway: {}", router);
					self.iface
						.routes_mut()
						.add_default_ipv4_route(router)
						.unwrap();
				} else {
					info!("Default gateway: None");
					self.iface.routes_mut().remove_default_ipv4_route();
				}

				for (i, s) in config.dns_servers.iter().enumerate() {
					if let Some(s) = s {
						info!("DNS server {}:    {}", i, s);
					}
				}
			}
			Some(Dhcpv4Event::Deconfigured) => {
				info!("DHCP lost config!");
				let cidr = Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0);
				self.iface.update_ip_addrs(|addrs| {
					let dest = addrs.iter_mut().next().unwrap();
					*dest = IpCidr::Ipv4(cidr);
				});
				self.iface.routes_mut().remove_default_ipv4_route();
			}
		};
	}

	pub(crate) fn poll(&mut self, cx: &mut Context<'_>, timestamp: Instant) {
		self.waker.register(cx.waker());
		self.poll_common(timestamp);
	}

	pub(crate) fn poll_delay(&mut self, timestamp: Instant) -> Option<Duration> {
		self.iface.poll_delay(timestamp)
	}
}

pub(crate) struct AsyncSocket(Handle);

impl AsyncSocket {
	pub(crate) fn new() -> Self {
		let handle = NIC.lock().as_nic_mut().unwrap().create_handle().unwrap();
		Self(handle)
	}

	fn with<R>(&self, f: impl FnOnce(&mut TcpSocket) -> R) -> R {
		let mut guard = NIC.lock();
		let nic = guard.as_nic_mut().unwrap();
		let res = {
			let s = nic.iface.get_socket::<TcpSocket>(self.0);
			f(s)
		};
		nic.wake();
		// just to flush send buffers
		let _ = nic.iface.poll(Instant::now());
		res
	}

	fn with_context<R>(&self, f: impl FnOnce(&mut TcpSocket, &mut iface::Context<'_>) -> R) -> R {
		let mut guard = NIC.lock();
		let nic = guard.as_nic_mut().unwrap();
		let res = {
			let (s, cx) = nic.iface.get_socket_and_context::<TcpSocket>(self.0);
			f(s, cx)
		};
		nic.wake();
		// just to flush send buffers
		let _ = nic.iface.poll(Instant::now());
		res
	}

	pub(crate) async fn connect(&self, ip: &[u8], port: u16) -> Result<Handle, NetworkError> {
		let address =
			IpAddress::from_str(std::str::from_utf8(ip).map_err(|_| NetworkError::InvalidInput)?)
				.map_err(|_| NetworkError::InvalidInput)?;

		self.with_context(|socket, cx| {
			socket.connect(
				cx,
				(address, port),
				LOCAL_ENDPOINT.fetch_add(1, Ordering::SeqCst),
			)
		})
		.map_err(|_| NetworkError::ConnectionRefused)?;

		future::poll_fn(|cx| {
			self.with(|socket| match socket.state() {
				TcpState::Closed | TcpState::TimeWait => {
					Poll::Ready(Err(NetworkError::ConnectionRefused))
				}
				TcpState::Listen => Poll::Ready(Err(NetworkError::ConnectionRefused)),
				TcpState::SynSent | TcpState::SynReceived => {
					socket.register_send_waker(cx.waker());
					Poll::Pending
				}
				_ => Poll::Ready(Ok(self.0)),
			})
		})
		.await
	}

	pub(crate) async fn accept(&self, port: u16) -> Result<(IpAddress, u16), NetworkError> {
		self.with(|socket| socket.listen(port).map_err(|_| NetworkError::InvalidInput))?;

		future::poll_fn(|cx| {
			self.with(|socket| {
				if socket.is_active() {
					Poll::Ready(Ok(()))
				} else {
					match socket.state() {
						TcpState::Closed
						| TcpState::Closing
						| TcpState::FinWait1
						| TcpState::FinWait2 => Poll::Ready(Err(NetworkError::InvalidInput)),
						_ => {
							socket.register_recv_waker(cx.waker());
							Poll::Pending
						}
					}
				}
			})
		})
		.await?;

		let mut guard = NIC.lock();
		let nic = guard.as_nic_mut().map_err(|_| NetworkError::Other)?;
		let socket = nic.iface.get_socket::<TcpSocket>(self.0);
		socket.set_keep_alive(Some(Duration::from_millis(DEFAULT_KEEP_ALIVE_INTERVAL)));
		let endpoint = socket.remote_endpoint();

		Ok((endpoint.addr, endpoint.port))
	}

	pub(crate) async fn read(&self, buffer: &mut [u8]) -> Result<usize, NetworkError> {
		future::poll_fn(|cx| {
			self.with(|socket| match socket.state() {
				TcpState::FinWait1
				| TcpState::FinWait2
				| TcpState::Closed
				| TcpState::Closing
				| TcpState::TimeWait => Poll::Ready(Err(NetworkError::NotConnected)),
				_ => {
					if !socket.may_recv() {
						Poll::Ready(Err(NetworkError::NotConnected))
					} else if socket.can_recv() {
						Poll::Ready(
							socket
								.recv_slice(buffer)
								.map_err(|_| NetworkError::ConnectionRefused),
						)
					} else {
						socket.register_recv_waker(cx.waker());
						Poll::Pending
					}
				}
			})
		})
		.await
	}

	pub(crate) async fn write(&self, buffer: &[u8]) -> Result<usize, NetworkError> {
		future::poll_fn(|cx| {
			self.with(|socket| match socket.state() {
				TcpState::FinWait1
				| TcpState::FinWait2
				| TcpState::Closed
				| TcpState::Closing
				| TcpState::TimeWait => Poll::Ready(Err(NetworkError::NotConnected)),
				_ => {
					if !socket.may_send() {
						Poll::Ready(Err(NetworkError::NotConnected))
					} else if socket.can_send() {
						Poll::Ready(
							socket
								.send_slice(buffer)
								.map_err(|_| NetworkError::ConnectionRefused),
						)
					} else {
						socket.register_send_waker(cx.waker());
						Poll::Pending
					}
				}
			})
		})
		.await
	}

	pub(crate) async fn close(&self) -> Result<(), NetworkError> {
		future::poll_fn(|cx| {
			self.with(|socket| match socket.state() {
				TcpState::FinWait1
				| TcpState::FinWait2
				| TcpState::Closed
				| TcpState::Closing
				| TcpState::TimeWait => Poll::Ready(Err(NetworkError::NotConnected)),
				_ => {
					if socket.send_queue() > 0 {
						socket.register_send_waker(cx.waker());
						Poll::Pending
					} else {
						socket.close();
						Poll::Ready(Ok(()))
					}
				}
			})
		})
		.await?;

		future::poll_fn(|cx| {
			self.with(|socket| match socket.state() {
				TcpState::FinWait1
				| TcpState::FinWait2
				| TcpState::Closed
				| TcpState::Closing
				| TcpState::TimeWait => Poll::Ready(Ok(())),
				_ => {
					socket.register_send_waker(cx.waker());
					Poll::Pending
				}
			})
		})
		.await
	}
}

impl From<Handle> for AsyncSocket {
	fn from(handle: Handle) -> Self {
		AsyncSocket(handle)
	}
}

#[cfg(target_arch = "x86_64")]
fn start_endpoint() -> u16 {
	((unsafe { _rdtsc() as u64 }) % (u16::MAX as u64))
		.try_into()
		.unwrap()
}

#[cfg(target_arch = "aarch64")]
fn start_endpoint() -> u16 {
	(CNTPCT_EL0.get() % (u16::MAX as u64)).try_into().unwrap()
}

pub(crate) fn network_delay(timestamp: Instant) -> Option<Duration> {
	NIC.lock().as_nic_mut().ok()?.poll_delay(timestamp)
}

pub(crate) async fn network_run() {
	future::poll_fn(|cx| match NIC.lock().deref_mut() {
		NetworkState::Initialized(nic) => {
			nic.poll(cx, Instant::now());
			Poll::Pending
		}
		_ => Poll::Ready(()),
	})
	.await
}

extern "C" fn nic_thread(_: usize) {
	loop {
		unsafe { sys_netwait() };

		trace!("Network thread checks the devices");

		if let NetworkState::Initialized(nic) = NIC.lock().deref_mut() {
			nic.poll_common(Instant::now());
			nic.wake();
		}
	}
}

pub(crate) fn network_init() -> Result<(), NetworkError> {
	// initialize variable, which contains the next local endpoint
	LOCAL_ENDPOINT.store(start_endpoint(), Ordering::SeqCst);

	let mut guard = NIC.lock();

	*guard = NetworkInterface::<HermitNet>::new();

	if let NetworkState::Initialized(nic) = guard.deref_mut() {
		nic.poll_common(Instant::now());

		// create thread, which manages the network stack
		// use a higher priority to reduce the network latency
		let mut tid: Tid = 0;
		let ret = unsafe { sys_spawn(&mut tid, nic_thread, 0, 3, 0) };
		if ret >= 0 {
			debug!("Spawn network thread with id {}", tid);
		}

		spawn(network_run()).detach();

		// switch to network thread
		unsafe { sys_yield() };
	}

	Ok(())
}

#[no_mangle]
pub fn sys_tcp_stream_connect(
	ip: &[u8],
	port: u16,
	timeout: Option<u64>,
) -> Result<Handle, NetworkError> {
	let socket = AsyncSocket::new();
	block_with_timeout_on(
		socket.connect(ip, port),
		timeout.map(Duration::from_millis),
		Err(NetworkError::TimedOut),
	)
}

/// makes the socket non_blocking
#[no_mangle]
pub fn sys_tcp_stream_set_non_blocking(
	handle: Handle,
	non_blocking: bool,
) -> Result<(), NetworkError> {
	let mut guard = SOCKET_MAP.lock();
	let socket_info = guard.get_mut(&handle).ok_or(NetworkError::InvalidSocket)?;
	socket_info.non_blocking = non_blocking;

	Ok(())
}

#[no_mangle]
pub fn sys_tcp_stream_read(handle: Handle, buffer: &mut [u8]) -> Result<usize, NetworkError> {
	let socket = AsyncSocket::from(handle);
	let info = *SOCKET_MAP
		.lock()
		.get(&handle)
		.ok_or(NetworkError::InvalidSocket)?;

	if !info.non_blocking {
		block_on(socket.read(buffer))
	} else {
		poll_on(socket.read(buffer), Err(NetworkError::WouldBlock))
	}
}

#[no_mangle]
pub fn sys_tcp_stream_write(handle: Handle, buffer: &[u8]) -> Result<usize, NetworkError> {
	let socket = AsyncSocket::from(handle);
	let info = *SOCKET_MAP
		.lock()
		.get(&handle)
		.ok_or(NetworkError::InvalidSocket)?;

	if !info.non_blocking {
		block_on(socket.write(buffer))
	} else {
		poll_on(socket.write(buffer), Err(NetworkError::WouldBlock))
	}
}

#[no_mangle]
pub fn sys_tcp_stream_close(handle: Handle) -> Result<(), NetworkError> {
	let socket = AsyncSocket::from(handle);
	block_on(socket.close())
}

//ToDo: an enum, or at least constants would be better
#[no_mangle]
pub fn sys_tcp_stream_shutdown(handle: Handle, how: i32) -> Result<(), NetworkError> {
	match how {
		0 /* Read */ => {
			trace!("Shutdown::Read is not implemented");
			Ok(())
		},
		1 /* Write */ => {
			sys_tcp_stream_close(handle)
		},
		2 /* Both */ => {
			sys_tcp_stream_close(handle)
		},
		_ => {
			panic!("Invalid shutdown argument {}", how);
		},
	}
}

#[no_mangle]
pub fn sys_tcp_stream_set_read_timeout(
	_handle: Handle,
	_timeout: Option<u64>,
) -> Result<(), NetworkError> {
	Err(NetworkError::Unsupported)
}

#[no_mangle]
pub fn sys_tcp_stream_get_read_timeout(_handle: Handle) -> Result<Option<u64>, NetworkError> {
	Err(NetworkError::Unsupported)
}

#[no_mangle]
pub fn sys_tcp_stream_set_write_timeout(
	_handle: Handle,
	_timeout: Option<u64>,
) -> Result<(), NetworkError> {
	Err(NetworkError::Unsupported)
}

#[no_mangle]
pub fn sys_tcp_stream_get_write_timeout(_handle: Handle) -> Result<Option<u64>, NetworkError> {
	Err(NetworkError::Unsupported)
}

#[deprecated(since = "0.1.14", note = "Please don't use this function")]
#[no_mangle]
pub fn sys_tcp_stream_duplicate(_handle: Handle) -> Result<Handle, NetworkError> {
	Err(NetworkError::Unsupported)
}

#[no_mangle]
pub fn sys_tcp_stream_peek(_handle: Handle, _buf: &mut [u8]) -> Result<usize, NetworkError> {
	Err(NetworkError::Unsupported)
}

#[no_mangle]
pub fn sys_tcp_stream_set_tll(_handle: Handle, _ttl: u32) -> Result<(), NetworkError> {
	Err(NetworkError::Unsupported)
}

#[no_mangle]
pub fn sys_tcp_stream_get_tll(_handle: Handle) -> Result<u32, NetworkError> {
	Err(NetworkError::Unsupported)
}

#[no_mangle]
pub fn sys_tcp_stream_peer_addr(handle: Handle) -> Result<(IpAddress, u16), NetworkError> {
	let mut guard = NIC.lock();
	let nic = guard.as_nic_mut().expect("Unable to get lock");
	let socket = nic.iface.get_socket::<TcpSocket>(handle);
	socket.set_keep_alive(Some(Duration::from_millis(DEFAULT_KEEP_ALIVE_INTERVAL)));
	let endpoint = socket.remote_endpoint();

	Ok((endpoint.addr, endpoint.port))
}

#[no_mangle]
pub fn sys_tcp_listener_accept(port: u16) -> Result<(Handle, IpAddress, u16), NetworkError> {
	let socket = AsyncSocket::new();
	let (addr, port) = block_on(socket.accept(port))?;

	Ok((socket.0, addr, port))
}
