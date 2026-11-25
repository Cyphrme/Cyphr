//! The HTTP listener: an accept loop with the bounds a public socket
//! needs, in place of `axum::serve`, which has none.
//!
//! - **Header read.** A client that does not finish its request head in
//!   [`Timeouts::header_read`] is dropped (slowloris).
//! - **The exchange.** From a request's first byte to the last byte of its
//!   response, [`Timeouts::request`]: a handler still running at the limit is
//!   answered `408`, and a client that drips its request or its read of the
//!   response is cut off [`DELIVERY_GRACE`] later, which is what the `408`
//!   needs to get out.
//! - **Idle.** A connection with no byte read or written for
//!   [`Timeouts::idle`] is closed: an idle keep-alive, or a peer that has
//!   stopped.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, Sleep};
use tower::ServiceExt;

/// How long after the exchange limit a connection is still let write: the
/// time a `408` has to leave.
const DELIVERY_GRACE: Duration = Duration::from_secs(1);

/// The listener's bounds, from `[limits]`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timeouts {
    pub(crate) header_read: Duration,
    pub(crate) request: Duration,
    pub(crate) idle: Duration,
}

/// Where one connection's current exchange stands, shared between its
/// stream and its service.
#[derive(Default)]
struct Exchange {
    /// When the first byte of the request that is being served arrived.
    started: Mutex<Option<Instant>>,
    /// Set when the response body has been handed over in full.
    finished: AtomicBool,
}

impl Exchange {
    fn started(&self) -> Option<Instant> {
        *self.started.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn set_started(&self, at: Option<Instant>) {
        *self.started.lock().unwrap_or_else(|p| p.into_inner()) = at;
    }
}

/// A stream that fails with `TimedOut` once nothing has moved for `idle`, or
/// once the exchange it is in has run past its limit and the grace.
struct BoundedStream {
    inner: TcpStream,
    idle: Duration,
    request: Duration,
    deadline: Pin<Box<Sleep>>,
    exchange: Arc<Exchange>,
    hard: Option<Pin<Box<Sleep>>>,
}

impl BoundedStream {
    fn new(inner: TcpStream, idle: Duration, request: Duration, exchange: Arc<Exchange>) -> Self {
        Self {
            inner,
            idle,
            request,
            deadline: Box::pin(tokio::time::sleep(idle)),
            exchange,
            hard: None,
        }
    }

    fn touch(&mut self) {
        self.deadline.as_mut().reset(Instant::now() + self.idle);
    }

    /// Refuse to go on with an exchange past its limit.
    fn check_exchange(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        if let Some(hard) = self.hard.as_mut()
            && hard.as_mut().poll(cx).is_ready()
        {
            // Reset, not a graceful close: a close would still deliver
            // every byte already queued to the slow reader. A zero linger
            // never blocks the drop; the deprecation is about a non-zero one.
            #[allow(deprecated)]
            let _ = self.inner.set_linger(Some(Duration::ZERO));
            return Poll::Ready(io::ErrorKind::TimedOut.into());
        }
        Poll::Pending
    }

    /// Note the first byte of a request: the exchange's clock starts.
    fn begin_exchange(&mut self) {
        if self.hard.is_none() {
            let now = Instant::now();
            self.exchange.set_started(Some(now));
            self.hard = Some(Box::pin(tokio::time::sleep_until(
                now + self.request + DELIVERY_GRACE,
            )));
        }
    }

    /// Fail a pending operation once the idle deadline has passed.
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

impl AsyncRead for BoundedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Poll::Ready(err) = self.check_exchange(cx) {
            return Poll::Ready(Err(err));
        }
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.begin_exchange();
        }
        self.bounded(cx, polled)
    }
}

impl AsyncWrite for BoundedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Poll::Ready(err) = self.check_exchange(cx) {
            return Poll::Ready(Err(err));
        }
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.bounded(cx, polled)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Poll::Ready(err) = self.check_exchange(cx) {
            return Poll::Ready(Err(err));
        }
        let polled = Pin::new(&mut self.inner).poll_flush(cx);
        // hyper flushes only once its write buffer is empty, so a flush that
        // completes after the body was handed over is the response's last
        // byte delivered: the exchange is over.
        if matches!(polled, Poll::Ready(Ok(()))) && self.exchange.finished.swap(false, Ordering::SeqCst)
        {
            self.hard = None;
            self.exchange.set_started(None);
        }
        self.bounded(cx, polled)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A response body that tells its connection when it has been handed over
/// in full; the exchange ends when the connection has also flushed it.
struct EndingBody {
    inner: Body,
    exchange: Arc<Exchange>,
}

impl EndingBody {
    fn new(inner: Body, exchange: Arc<Exchange>) -> Self {
        if hyper::body::Body::is_end_stream(&inner) {
            exchange.finished.store(true, Ordering::SeqCst);
        }
        Self { inner, exchange }
    }
}

impl hyper::body::Body for EndingBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(polled, Poll::Ready(None | Some(Err(_)))) {
            self.exchange.finished.store(true, Ordering::SeqCst);
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        hyper::body::Body::is_end_stream(&self.inner)
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::Body::size_hint(&self.inner)
    }
}

/// Serve `app` on `listener` until `shutdown` resolves, then let the
/// connections in flight finish (each is bounded by the limits above).
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
        let exchange = Arc::new(Exchange::default());
        let service = app.clone().layer(axum::Extension(ConnectInfo(peer)));
        let service_exchange = exchange.clone();
        let request_limit = timeouts.request;
        let hyper_service = hyper::service::service_fn(move |request| {
            let service = service.clone();
            let exchange = service_exchange.clone();
            async move {
                let deadline = exchange.started().unwrap_or_else(Instant::now) + request_limit;
                let response =
                    match tokio::time::timeout_at(deadline, service.oneshot(request)).await {
                        Ok(Ok(response)) => response.map(Body::new),
                        Ok(Err(never)) => match never {},
                        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
                    };
                Ok::<Response<EndingBody>, Infallible>(
                    response.map(|body| EndingBody::new(body, exchange)),
                )
            }
        });
        let connection = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(timeouts.header_read)
            .serve_connection(
                TokioIo::new(BoundedStream::new(
                    stream,
                    timeouts.idle,
                    timeouts.request,
                    exchange,
                )),
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

#[cfg(test)]
mod tests {
    use std::time::Instant as StdInstant;

    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    const BIG: usize = 96 * 1024 * 1024;

    fn limits(request: u64) -> Timeouts {
        Timeouts {
            header_read: Duration::from_secs(10),
            request: Duration::from_secs(request),
            idle: Duration::from_secs(120),
        }
    }

    /// A listener over a router with `/big` (a body far past the socket
    /// buffers) and `/ok`, and its address.
    async fn start(timeouts: Timeouts) -> SocketAddr {
        let app = axum::Router::new()
            .route("/big", get(|| async { vec![7u8; BIG] }))
            .route("/ok", get(|| async { "ok" }));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(serve(listener, app, timeouts, std::future::pending()));
        addr
    }

    /// Claim: a client that reads a large response slowly is cut off at the
    /// exchange deadline, long before the idle timeout (120 s here), and the
    /// response is not delivered whole. Turns red if the limit bounds only the
    /// handler, so a dripping reader keeps the connection.
    /// End-to-end scenario: yes (a real listener and a real socket).
    #[tokio::test]
    async fn a_client_that_drips_its_read_is_cut_off_at_the_deadline() {
        let addr = start(limits(1)).await;
        let socket = tokio::net::TcpSocket::new_v4().expect("socket");
        socket.set_recv_buffer_size(4096).expect("rcvbuf");
        let mut client = socket.connect(addr).await.expect("connect");
        client
            .write_all(b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect("request");
        let started = StdInstant::now();
        let mut received = 0usize;
        let mut buf = [0u8; 1024];
        loop {
            match client.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => received += n,
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                started.elapsed() < Duration::from_secs(15),
                "still connected after {:?}",
                started.elapsed()
            );
        }
        assert!(received < BIG, "the response was delivered whole");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "cut off late: {:?}",
            started.elapsed()
        );
    }
}
