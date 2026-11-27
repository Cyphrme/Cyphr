//! The carrier seam: how bytes move between a client and a peer.
//!
//! Scenarios and the fault proxy talk to peers only through these traits,
//! so adding the Noise XX transport later is a new [`Carrier`] impl and
//! touches no scenario. The traits are object-safe on purpose (`Box<dyn
//! Duplex>`, `BoxFuture`), the same shape tokio-util and tower use for
//! transport-erased connections.

use std::io;
use std::net::{IpAddr, SocketAddr};

use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket};

/// A bidirectional byte stream. Blanket-implemented so any suitable
/// stream (TCP today, a Noise session later) is a `Duplex`.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// The listening half of a carrier.
pub trait Accept: Send {
    fn accept(&mut self) -> BoxFuture<'_, io::Result<(Box<dyn Duplex>, SocketAddr)>>;
    fn local_addr(&self) -> SocketAddr;
}

/// A transport: bind a listener, or connect to an address, optionally from
/// a chosen local source IP so the far side sees one address per node.
pub trait Carrier: Send + Sync + 'static {
    fn bind(&self) -> BoxFuture<'_, io::Result<Box<dyn Accept>>>;
    fn connect(
        &self,
        addr: SocketAddr,
        src: Option<IpAddr>,
    ) -> BoxFuture<'_, io::Result<Box<dyn Duplex>>>;
}

/// Ask the kernel to choose a bound socket's port at connect time instead of
/// at bind (`IP_BIND_ADDRESS_NO_PORT`).
#[cfg(target_os = "linux")]
fn defer_port_choice(socket: &TcpSocket) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let on: libc::c_int = 1;
    // SAFETY: the descriptor is a live socket that `socket` owns for the
    // whole call, and `on` outlives it with the length passed being its size.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_BIND_ADDRESS_NO_PORT,
            std::ptr::from_ref(&on).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Source addresses are only bound on Linux, where all of 127.0.0.0/8 is
/// local; elsewhere `connect` is never given one.
#[cfg(not(target_os = "linux"))]
fn defer_port_choice(_: &TcpSocket) -> io::Result<()> {
    Ok(())
}

/// Plain TCP on the loopback interface; the OS assigns the port.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpCarrier;

struct TcpAccept {
    listener: TcpListener,
    local: SocketAddr,
}

impl Accept for TcpAccept {
    fn accept(&mut self) -> BoxFuture<'_, io::Result<(Box<dyn Duplex>, SocketAddr)>> {
        Box::pin(async move {
            let (stream, peer) = self.listener.accept().await?;
            Ok((Box::new(stream) as Box<dyn Duplex>, peer))
        })
    }

    fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

impl Carrier for TcpCarrier {
    fn bind(&self) -> BoxFuture<'_, io::Result<Box<dyn Accept>>> {
        Box::pin(async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
            let local = listener.local_addr()?;
            Ok(Box::new(TcpAccept { listener, local }) as Box<dyn Accept>)
        })
    }

    fn connect(
        &self,
        addr: SocketAddr,
        src: Option<IpAddr>,
    ) -> BoxFuture<'_, io::Result<Box<dyn Duplex>>> {
        Box::pin(async move {
            let socket = TcpSocket::new_v4()?;
            if let Some(ip) = src {
                // Without this, bind(port 0) reserves a port per source IP
                // regardless of destination, and TIME_WAIT strands the range
                // (SO_REUSEADDR does not prevent that: a bound port is taken
                // whatever the destination). With it, the kernel picks the
                // port at connect, where only the full address pair must be
                // unique.
                defer_port_choice(&socket)?;
                socket.bind(SocketAddr::new(ip, 0))?;
            }
            Ok(Box::new(socket.connect(addr).await?) as Box<dyn Duplex>)
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// The ephemeral port range of this host, from the kernel.
    fn ephemeral_ports() -> usize {
        let text = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .expect("reading the ephemeral port range");
        let mut ends = text.split_whitespace().map(|n| n.parse::<usize>());
        match (ends.next(), ends.next()) {
            (Some(Ok(lo)), Some(Ok(hi))) => hi - lo + 1,
            _ => panic!("unreadable ephemeral port range: {text:?}"),
        }
    }

    // A node under gossip opens far more short connections than one source
    // IP has ephemeral ports, to many different peers. Binding before
    // connect must not make every connection burn a port of the source IP
    // whatever its destination: the side that closes first is left in
    // TIME_WAIT, here the client's, so a port chosen at bind is stranded per
    // connection and the range runs out, while a port chosen at connect only
    // collides on a repeat of the same (source, destination) pair. Every connection here
    // goes to a distinct destination address of one listener, so only the
    // missing fix can fail it. The count is the host's own range plus 10%, so
    // a host with a wider range cannot pass without the fix.
    #[tokio::test]
    async fn one_source_ip_survives_more_connections_than_ports() {
        let listener = TcpListener::bind(("0.0.0.0", 0)).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = tokio::io::AsyncReadExt::read(&mut s, &mut [0u8; 1]).await;
                });
            }
        });
        // A source address of this process's own, so connections lingering
        // in TIME_WAIT from an earlier run cannot collide with this one.
        let pid = std::process::id();
        let src = Some(IpAddr::from([127, 9, (pid >> 8) as u8, pid as u8]));
        let ports = ephemeral_ports();
        for i in 0..ports + ports / 10 {
            let dst = SocketAddr::new(IpAddr::from([127, 20, (i >> 8) as u8, i as u8]), port);
            let c = TcpCarrier.connect(dst, src).await;
            assert!(
                c.is_ok(),
                "connect {i} of {ports} ports failed: {:?}",
                c.err()
            );
        }
    }
}
