use std::net::{SocketAddr, ToSocketAddrs};

use bytes::{Buf, BufMut, Bytes};
use quinn::{ApplicationClose, ConnectionError};
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::{pki_types::CertificateDer, server::ParsedCertificate};
use url::Url;
use web_transport::SessionError;
use web_transport_quinn::{self as web_transport, quinn, quinn::rustls};

use crate::{Endpoint, Error, normalise_addrs};

trait SessionInner {
    fn as_inner(&self) -> web_transport::Session;
}

/// A Session, able to accept/create streams and send/recv datagrams.
///
/// Can be cloned to create multiple handles to the same underlying connection.
///
/// If all references to a connection (including every clone of the `Session` handle, streams of
/// incoming streams, and the various stream types) have been dropped, then the session will be
/// automatically closed with a `code` of 0 and an empty reason. You can also close the session
/// explicitly by calling [`Session::close()`].
///
/// Closing the session immediately immediately sends a `CONNECTION_CLOSE` frame and then abandons
/// efforts to deliver data to the peer. Upon receiving `CONNECTION_CLOSE` the peer may drop any
/// stream data not yet delivered to the application. [`Session::close()`] describes in more detail
/// how to gracefully close a session without losing application data.
#[allow(async_fn_in_trait, private_bounds)]
pub trait Session: SessionInner + std::fmt::Debug + Clone + Send + Sync + 'static {
    /// The public key of the remote peer.
    ///
    /// This may be unavailable if `require_client_auth` returned `false` in the Endpoint's
    /// [`AllowConnection`] instance.
    fn peer_key(&self) -> Option<&SubjectPublicKeyInfoDer<'_>>;

    /// Get access to the underlying QUIC Connection.
    ///
    /// # Safety
    ///
    /// You must not use any methods that alter the session state, nor any that send packets.
    /// This may corrupt the WebTransport state layered on top.
    ///
    /// Accessing statistical and factual information (such as `peer_identity()`,
    /// `remote_address()`, `stats()`, `close_reason()`, etc) is safe.
    unsafe fn quic(&self) -> quinn::Connection {
        (*self.as_inner()).clone()
    }

    /// Wait until the peer creates a new unidirectional stream.
    ///
    /// Will error if the connection is closed.
    async fn accept_uni(&self) -> Result<RecvStream, Error> {
        let inner = self.as_inner().clone();
        let stream = inner.accept_uni().await?;
        Ok(RecvStream::new(stream))
    }

    /// Wait until the peer creates a new bidirectional stream.
    ///
    /// Will error if the connection is closed.
    async fn accept_bi(&self) -> Result<(SendStream, RecvStream), Error> {
        let (s, r) = self.as_inner().clone().accept_bi().await?;
        Ok((SendStream::new(s), RecvStream::new(r)))
    }

    /// Open a new bidirectional stream.
    ///
    /// May wait when there are too many concurrent streams.
    ///
    /// Will error if the connection is closed.
    async fn open_bi(&self) -> Result<(SendStream, RecvStream), Error> {
        let inner = self.as_inner().clone();
        Ok(inner
            .open_bi()
            .await
            .map(|(s, r)| (SendStream::new(s), RecvStream::new(r)))?)
    }

    /// Open a new unidirectional stream.
    ///
    /// May wait when there are too many concurrent streams.
    ///
    /// Will error if the connection is closed.
    async fn open_uni(&self) -> Result<SendStream, Error> {
        let inner = self.as_inner().clone();
        Ok(inner.open_uni().await.map(SendStream::new)?)
    }

    /// Send an unreliable datagram over the network.
    ///
    /// QUIC datagrams may be dropped for any reason, including (non-exhaustive):
    /// - Network congestion
    /// - Random packet loss
    /// - Payload is larger than `max_datagram_size()`
    /// - Peer is not receiving datagrams
    /// - Peer has too many outstanding datagrams
    ///
    /// Will error if the connection is closed.
    fn send_datagram(&self, payload: Bytes) -> Result<(), Error> {
        let inner = self.as_inner().clone();
        Ok(inner.send_datagram(payload)?)
    }

    /// The maximum size of a datagram that can be sent.
    fn max_datagram_size(&self) -> usize {
        self.as_inner().max_datagram_size()
    }

    /// Receive a datagram over the network.
    ///
    /// Will error if the connection is closed.
    async fn recv_datagram(&self) -> Result<Bytes, Error> {
        let inner = self.as_inner().clone();
        Ok(inner.read_datagram().await?)
    }

    /// Close the session immediately.
    ///
    /// Pending operations will fail immediately with `Connection(ConnectionError::LocallyClosed)`.
    /// No more data is sent to the peer beyond a `CONNECTION_CLOSE` frame, and the peer may drop
    /// buffered data upon receiving the `CONNECTION_CLOSE` frame.
    ///
    /// `code` and `reason` are not interpreted, and are provided directly to the peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to improve odds that it
    /// is preserved in full, it should be kept under 1KiB.
    ///
    /// # Gracefully closing a session
    ///
    /// Only the peer last receiving application data can be certain that all data is delivered.
    /// The only reliable action it can then take is to close the session, potentially with a
    /// custom error code. The delivery of the final `CONNECTION_CLOSE` frame is very likely if
    /// both endpoints stay online long enough, and [`Endpoint::wait_idle()`] can be used to
    /// provide sufficient time. Otherwise, the remote peer will time out the session after 30
    /// seconds.
    ///
    /// The sending side can not guarantee all stream data is delivered to the remote application.
    /// It only knows the data is delivered to the QUIC stack of the remote endpoint. Once the
    /// local side sends a `CONNECTION_CLOSE` frame, the remote endpoint may drop any data it
    /// received but is as yet undelivered to the application, including data that was acknowledged
    /// as received to the local endpoint.
    fn close(&self, code: u32, reason: impl AsRef<[u8]>) {
        let inner = self.as_inner().clone();
        inner.close(code, reason.as_ref())
    }

    /// Wait until the connection is closed.
    ///
    /// Returns `Ok(None)` if the connection was closed locally, `Ok(Some(_))` if the connection
    /// was closed by a peer (e.g. with `close()`), and `Err(_)` for other unexpected reasons.
    async fn closed(&self) -> Result<Option<ApplicationClose>, Error> {
        match self.as_inner().clone().closed().await {
            SessionError::ConnectionError(ConnectionError::LocallyClosed) => Ok(None),
            SessionError::ConnectionError(ConnectionError::ApplicationClosed(ac)) => Ok(Some(ac)),
            e => Err(Error::Session(e)),
        }
    }
}

/// A session created by `connect()`.
///
/// See [`Session`] for common methods.
#[derive(Debug, Clone)]
pub struct ConnectedSession {
    addrs: Vec<SocketAddr>,
    endpoint: Endpoint,
    peer_key: Option<SubjectPublicKeyInfoDer<'static>>,
    inner: AcceptedSession,
}

impl ConnectedSession {
    async fn connect_impl(
        endpoint: &Endpoint,
        addrs: &[SocketAddr],
    ) -> Result<web_transport::Session, Error> {
        let mut last_err = None;
        for addr in addrs {
            let url = Url::parse(&format!("https://{addr}")).unwrap();
            let conn = endpoint.endpoint.connect_with(
                endpoint.client_config.clone(),
                *addr,
                "mushi.mushi",
            )?;
            let conn = conn.await?;

            match web_transport::Session::connect(conn, &url).await {
                Ok(s) => return Ok(s),
                Err(e) => last_err = Some(Error::from(e)),
            }
        }

        Err(last_err.unwrap_or(Error::NoAddrs))
    }

    pub(crate) async fn new(endpoint: Endpoint, addrs: Vec<SocketAddr>) -> Result<Self, Error> {
        let session = Self::connect_impl(&endpoint, &addrs).await?;
        Ok(Self {
            addrs,
            endpoint,
            peer_key: obtain_peer_key(&session),
            inner: AcceptedSession {
                session,
                peer_key: None,
            },
        })
    }

    /// Reconnect the session (e.g. after it timed out).
    ///
    /// This re-uses the addresses provided in the initial `connect()` call. Note that DNS is not
    /// resolved again; if that's desired use [`reconnect_to()`][ConnectedSession::reconnect_to].
    ///
    /// The key of the peer must match the one previously obtained.
    ///
    /// This does not modify other clones of the session.
    pub async fn reconnect(self) -> Result<Self, Error> {
        let session = Self::connect_impl(&self.endpoint, &self.addrs).await?;
        let new_peer_key = obtain_peer_key(&session);
        if new_peer_key != self.peer_key {
            return Err(Error::PeerKeyMismatch);
        }
        Ok(Self {
            endpoint: self.endpoint,
            addrs: self.addrs,
            peer_key: self.peer_key,
            inner: AcceptedSession {
                session,
                peer_key: None,
            },
        })
    }

    /// Reconnect the session to new addresses.
    ///
    /// This can be used if the address of the peer has changed, or to resolve DNS again.
    ///
    /// The key of the peer must match the one previously obtained.
    pub async fn reconnect_to(mut self, addrs: impl ToSocketAddrs) -> Result<Self, Error> {
        self.addrs = normalise_addrs(addrs)?;
        self.reconnect().await
    }
}

impl Session for ConnectedSession {
    fn peer_key(&self) -> Option<&SubjectPublicKeyInfoDer<'_>> {
        self.peer_key.as_ref()
    }
}

impl SessionInner for ConnectedSession {
    fn as_inner(&self) -> web_transport::Session {
        self.inner.as_inner().clone()
    }
}

/// A session created by `accept()`.
///
/// Accepted sessions are subject to getting disconnected from timeouts or network conditions
/// without direct recourse (besides waiting for the peer to reconnect).
///
/// See [`Session`] for common methods.
#[derive(Debug, Clone)]
pub struct AcceptedSession {
    pub(crate) session: web_transport::Session,
    pub(crate) peer_key: Option<SubjectPublicKeyInfoDer<'static>>,
}

impl Session for AcceptedSession {
    fn peer_key(&self) -> Option<&SubjectPublicKeyInfoDer<'_>> {
        self.peer_key.as_ref()
    }
}

impl SessionInner for AcceptedSession {
    fn as_inner(&self) -> web_transport::Session {
        self.session.clone()
    }
}

pub(crate) fn obtain_peer_key(
    conn: &quinn::Connection,
) -> Option<SubjectPublicKeyInfoDer<'static>> {
    conn.peer_identity().and_then(|id| {
        let certs: Vec<CertificateDer> = *id.downcast().ok()?;
        for cert in certs {
            let Ok(cert) = ParsedCertificate::try_from(&cert) else {
                continue;
            };
            return Some(cert.subject_public_key_info());
        }

        None
    })
}

/// An outgoing stream of bytes to the peer.
///
/// QUIC streams have flow control, which means the send rate is limited by the peer's receive
/// window. The stream will be closed with a graceful FIN when dropped.
#[derive(Debug)]
pub struct SendStream {
    inner: web_transport::SendStream,
}

impl SendStream {
    fn new(inner: web_transport::SendStream) -> Self {
        Self { inner }
    }

    /// Write *all* of the buffer to the stream.
    pub async fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.inner.write_all(buf).await?;
        Ok(())
    }

    /// Write the given buffer to the stream, advancing the internal position.
    ///
    /// This may be polled to perform partial writes.
    pub async fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Result<(), Error> {
        while buf.has_remaining() {
            let size = self.inner.write(buf.chunk()).await?;
            buf.advance(size);
        }

        Ok(())
    }

    /// Set the stream's priority.
    ///
    /// Streams with lower values will be sent first, but are not guaranteed to arrive first.
    pub fn set_priority(&mut self, order: i32) {
        self.inner.set_priority(order).ok();
    }

    /// Send an immediate reset code, closing the stream.
    pub fn reset(&mut self, code: u32) {
        self.inner.reset(code).ok();
    }
}

/// An incoming stream of bytes from the peer.
///
/// All bytes are flushed in order and the stream is flow controlled.
///
/// The stream will be closed with STOP_SENDING code=0 when dropped.
#[derive(Debug)]
pub struct RecvStream {
    inner: web_transport::RecvStream,
}

impl RecvStream {
    fn new(inner: web_transport::RecvStream) -> Self {
        Self { inner }
    }

    /// Read the next chunk of data with the provided maximum size.
    ///
    /// This returns a chunk of data instead of copying, which may be more efficient.
    pub async fn read(&mut self, max: usize) -> Result<Option<Bytes>, Error> {
        Ok(self
            .inner
            .read_chunk(max, true)
            .await?
            .map(|chunk| chunk.bytes))
    }

    /// Read some data into the provided buffer.
    ///
    /// The number of bytes read is returned, or None if the stream is closed.
    ///
    /// The buffer will be advanced by the number of bytes read.
    pub async fn read_buf<B: BufMut>(&mut self, buf: &mut B) -> Result<Option<usize>, Error> {
        let dst = buf.chunk_mut();
        let dst = unsafe { &mut *(dst as *mut _ as *mut [u8]) };

        let size = match self.inner.read(dst).await? {
            Some(size) => size,
            None => return Ok(None),
        };

        unsafe { buf.advance_mut(size) };

        Ok(Some(size))
    }

    /// Send a `STOP_SENDING` QUIC code.
    pub fn stop(&mut self, code: u32) {
        self.inner.stop(code).ok();
    }
}
