//! The HTTP listener: an accept loop with the timeouts a public socket
//! needs, in place of `axum::serve`, which has none.
//!
//! - **Header read.** A client that does not finish its request head in [`Timeouts::header_read`]
//!   is dropped (slowloris).
//! - **Idle.** A connection with no byte read or written for [`Timeouts::idle`] is closed, which
//!   also ends an idle keep-alive.
//! - The whole-request bound is a layer on the router ([`crate::build_app_router`]), so it covers
//!   the body a handler reads.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::ConnectInfo;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, Sleep};
use tower::ServiceExt;

/// The connection-level bounds, from `[limits]`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timeouts {
    pub(crate) header_read: Duration,
    pub(crate) idle: Duration,
}

/// A stream that fails a read with `TimedOut` once nothing has been read or
/// written for `idle`.
struct IdleStream {
    inner: TcpStream,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
}

impl IdleStream {
    fn new(inner: TcpStream, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
        }
    }

    fn touch(&mut self) {
        self.deadline.as_mut().reset(Instant::now() + self.idle);
    }
}

impl AsyncRead for IdleStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                self.touch();
                Poll::Ready(result)
            },
            Poll::Pending => match self.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::ErrorKind::TimedOut.into())),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl IdleStream {
    /// The write side of the idle bound: a write the peer is not draining
    /// (a client that does not read its response, or drips it) fails with
    /// `TimedOut` once `idle` passes with no progress, as a silent read does.
    fn bounded<T>(
        &mut self,
        cx: &mut Context<'_>,
        polled: Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        match polled {
            Poll::Ready(result) => {
                if result.is_ok() {
                    self.touch();
                }
                Poll::Ready(result)
            },
            Poll::Pending => match self.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::ErrorKind::TimedOut.into())),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl AsyncWrite for IdleStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.bounded(cx, polled)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_flush(cx);
        self.bounded(cx, polled)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Serve `app` on `listener` until `shutdown` resolves, then let the
/// connections in flight finish (each is bounded by the idle timeout).
///
/// Every request carries the peer's [`ConnectInfo`], which the per-IP fence
/// keys on.
pub(crate) async fn serve(
    listener: TcpListener,
    app: axum::Router,
    timeouts: Timeouts,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        let (stream, peer): (TcpStream, SocketAddr) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                // A failed accept (a connection reset before it was taken,
                // or out of file descriptors) is that connection's, not the
                // listener's.
                Err(err) => {
                    tracing::warn!(%err, "accepting a connection failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                },
            },
            () = &mut shutdown => break,
        };
        let service = app.clone().layer(axum::Extension(ConnectInfo(peer)));
        let hyper_service =
            hyper::service::service_fn(move |request| service.clone().oneshot(request));
        let connection = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(timeouts.header_read)
            .serve_connection(
                TokioIo::new(IdleStream::new(stream, timeouts.idle)),
                hyper_service,
            );
        let connection = graceful.watch(connection);
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::debug!(%err, %peer, "connection ended with an error");
            }
        });
    }
    graceful.shutdown().await;
    Ok(())
}
