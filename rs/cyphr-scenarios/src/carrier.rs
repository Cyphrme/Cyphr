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

/// Which wire a carrier rides on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierKind {
    Tcp,
    Udp,
}

/// A transport: bind a listener, or connect to an address, optionally from
/// a chosen local source IP so the far side sees one address per node.
pub trait Carrier: Send + Sync + 'static {
    fn kind(&self) -> CarrierKind;
    fn bind(&self) -> BoxFuture<'_, io::Result<Box<dyn Accept>>>;
    fn connect(
        &self,
        addr: SocketAddr,
        src: Option<IpAddr>,
    ) -> BoxFuture<'_, io::Result<Box<dyn Duplex>>>;
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
    fn kind(&self) -> CarrierKind {
        CarrierKind::Tcp
    }

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
                // regardless of destination, and TIME_WAIT strands the range.
                socket.set_reuseaddr(true)?;
                socket.bind(SocketAddr::new(ip, 0))?;
            }
            Ok(Box::new(socket.connect(addr).await?) as Box<dyn Duplex>)
        })
    }
}

/// The datagram carrier slot. It exists so the seam's two kinds are both
/// representable; every operation reports `Unsupported` until a transport
/// needs it.
#[derive(Clone, Copy, Debug, Default)]
pub struct UdpCarrier;

fn unsupported<T>() -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the Udp carrier is not implemented",
    ))
}

impl Carrier for UdpCarrier {
    fn kind(&self) -> CarrierKind {
        CarrierKind::Udp
    }

    fn bind(&self) -> BoxFuture<'_, io::Result<Box<dyn Accept>>> {
        Box::pin(async { unsupported() })
    }

    fn connect(
        &self,
        _addr: SocketAddr,
        _src: Option<IpAddr>,
    ) -> BoxFuture<'_, io::Result<Box<dyn Duplex>>> {
        Box::pin(async { unsupported() })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // A node under gossip opens far more short connections than one source
    // IP has ephemeral ports; binding before connect must not strand them in
    // TIME_WAIT.
    #[tokio::test]
    async fn one_source_ip_survives_more_connections_than_ports() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let dst = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                drop(s);
            }
        });
        let src = Some(IpAddr::from([127, 0, 0, 2]));
        for i in 0..35_000 {
            let c = TcpCarrier.connect(dst, src).await;
            assert!(c.is_ok(), "connect {i} failed: {:?}", c.err());
        }
    }
}
