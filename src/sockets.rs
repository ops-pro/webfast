//! The sockets clients connect to, tuned (Linux; other systems keep their defaults). Options are
//! set on the listening socket and inherited by every connection it accepts; one the system
//! refuses is left as it is, and the server says so once at startup.
//!
//! TCP:
//! - congestion control `WEB_TCP_CONGESTION` (`bbr` by default: steadier on long, lossy paths than
//!   cubic; the kernel must have it and allow it, see README.md);
//! - `TCP_NOTSENT_LOWAT` 16 KiB: the kernel holds little unsent data, so HTTP/2 can still put an
//!   urgent stream ahead of a long one (and less sits in buffers for a client that went away);
//! - `TCP_DEFER_ACCEPT`: a connection reaches the server only once it has sent data;
//! - `TCP_USER_TIMEOUT` = the stall limit: data the peer does not acknowledge (or a window it keeps
//!   closed) for that long ends the connection in the kernel; keepalive probes find vanished peers
//!   on idle connections after about 90 s;
//! - a listen backlog of 4096 (the kernel caps it at `net.core.somaxconn`).
//!
//! UDP (HTTP/3): 4 MiB receive and send buffers (capped at `net.core.rmem_max` / `wmem_max`): UDP has
//! no autotuning, and the default ~200 KB drops packets when they arrive in bursts.

use crate::config::Limits;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::net::SocketAddr;
use std::time::Duration;

const BACKLOG: i32 = 4096;
const NOTSENT_LOWAT: u32 = 16 * 1024;
const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_PROBES: u32 = 3;
const UDP_BUFFER: usize = 4 << 20;

/// A listening TCP socket for `address`, and the options the system refused.
pub fn tcp_listener(address: SocketAddr, limits: &Limits) -> std::io::Result<(tokio::net::TcpListener, Vec<String>)> {
    let socket = Socket::new(Domain::for_address(address), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    let mut refused = Vec::new();
    let mut note = |what: &str, result: std::io::Result<()>| {
        if let Err(e) = result {
            refused.push(format!("{what}: {e}"));
        }
    };
    note("TCP_NODELAY", socket.set_tcp_nodelay(true));
    note(
        "keepalive",
        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(KEEPALIVE_IDLE)
                .with_interval(KEEPALIVE_INTERVAL)
                .with_retries(KEEPALIVE_PROBES),
        ),
    );
    #[cfg(target_os = "linux")]
    {
        note("TCP_NOTSENT_LOWAT", socket.set_tcp_notsent_lowat(NOTSENT_LOWAT));
        note("TCP_USER_TIMEOUT", socket.set_tcp_user_timeout(Some(limits.stall)));
        note("TCP_DEFER_ACCEPT", defer_accept(&socket, limits.read_header));
        if let Some(name) = limits.tcp_congestion {
            note(
                &format!("congestion control {name} (net.ipv4.tcp_allowed_congestion_control)"),
                socket.set_tcp_congestion(name.as_bytes()),
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (NOTSENT_LOWAT, limits);
    socket.bind(&address.into())?;
    socket.listen(BACKLOG)?;
    let listener = tokio::net::TcpListener::from_std(socket.into())?;
    Ok((listener, refused))
}

/// The congestion control a socket uses (Linux), for the startup log.
pub fn congestion_of(listener: &tokio::net::TcpListener) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let name = SockRef::from(listener).tcp_congestion().ok()?;
        let name = name.split(|b| *b == 0).next().unwrap_or_default();
        Some(String::from_utf8_lossy(name).into_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = listener;
        None
    }
}

/// A connection reaches `accept` only once data has arrived (at most `wait`; the client of a
/// browser sends its ClientHello or request at once).
#[cfg(target_os = "linux")]
fn defer_accept(socket: &Socket, wait: Duration) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let seconds = libc::c_int::try_from(wait.as_secs().max(1)).unwrap_or(libc::c_int::MAX);
    // SAFETY: a valid socket and a pointer to a c_int that outlives the call, with its size.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_DEFER_ACCEPT,
            (&seconds as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// A UDP socket for QUIC on `address`, with large buffers; their sizes as the kernel gave them
/// (Linux reports twice what it sets aside, for its bookkeeping).
pub fn udp_socket(address: SocketAddr) -> std::io::Result<(std::net::UdpSocket, usize, usize)> {
    let socket = Socket::new(Domain::for_address(address), Type::DGRAM, Some(Protocol::UDP))?;
    if address.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    // Asked for; the kernel caps them at net.core.rmem_max / wmem_max.
    let _ = socket.set_recv_buffer_size(UDP_BUFFER);
    let _ = socket.set_send_buffer_size(UDP_BUFFER);
    socket.bind(&address.into())?;
    let receive = socket.recv_buffer_size().unwrap_or(0);
    let send = socket.send_buffer_size().unwrap_or(0);
    Ok((socket.into(), receive, send))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accepted_connections_inherit_the_listening_socket_options() {
        let limits = Limits {
            tcp_congestion: Some("reno"),
            ..Limits::default()
        };
        let (listener, refused) = tcp_listener("127.0.0.1:0".parse().unwrap(), &limits).unwrap();
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(congestion_of(&listener).as_deref(), Some("reno"));
        let address = listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        // Deferred accept: nothing arrives at `accept` until the client sends.
        let accepted = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
        assert!(accepted.is_err(), "accepted before any data");
        tokio::io::AsyncWriteExt::write_all(&mut client, b"GET / HTTP/1.1\r\n")
            .await
            .unwrap();
        let (stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("accepted once data came")
            .unwrap();
        let socket = SockRef::from(&stream);
        let congestion = socket.tcp_congestion().unwrap();
        assert_eq!(congestion.split(|b| *b == 0).next().unwrap(), b"reno");
        assert_eq!(socket.tcp_notsent_lowat().unwrap(), NOTSENT_LOWAT);
        assert_eq!(socket.tcp_user_timeout().unwrap(), Some(limits.stall));
        assert!(socket.keepalive().unwrap());
        assert_eq!(socket.tcp_keepalive_time().unwrap(), KEEPALIVE_IDLE);
        assert!(socket.tcp_nodelay().unwrap());
    }

    #[test]
    fn an_unknown_congestion_control_is_reported_not_fatal() {
        let limits = Limits {
            tcp_congestion: Some("no-such-algorithm"),
            ..Limits::default()
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let (listener, refused) = tcp_listener("127.0.0.1:0".parse().unwrap(), &limits).unwrap();
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("congestion control no-such-algorithm"));
        assert!(congestion_of(&listener).is_some(), "the system's default stays");
    }

    #[test]
    fn udp_buffers_are_raised() {
        let (_socket, receive, send) = udp_socket("127.0.0.1:0".parse().unwrap()).unwrap();
        // At least what the system allows above its default (~200 KB).
        assert!(receive > 256 * 1024 && send > 256 * 1024, "{receive} {send}");
    }
}
