use std::{
    net::ToSocketAddrs,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use mushi::{
    StatusCode,
    quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig},
};
use napi::bindgen_prelude::*;
use napi_derive::*;
use tokio::sync::Mutex;

fn err(prefix: &str, e: impl std::fmt::Display) -> Error {
    Error::from_reason(format!("{prefix}: {e}"))
}

/// The long-lived key pair identifying a Mushi server.
///
/// The key outlives the certificates issued from it. Browsers pin the certificate rather than the
/// key, so rotating a certificate changes the hash even when the key stays the same.
#[napi]
#[derive(Debug, Clone)]
pub struct Identity(mushi::Identity);

#[napi]
impl Identity {
    /// Load an identity from a PEM-encoded PKCS#8 private key.
    ///
    /// Errors if the key isn't ECDSA P-256, which is the only scheme browsers accept.
    #[napi(constructor)]
    pub fn new(private_key_pem: String) -> Result<Self> {
        mushi::Identity::from_pem(&private_key_pem)
            .map(Self)
            .map_err(|e| err("identity", e))
    }

    /// Generate a new random identity using ECDSA P-256.
    #[napi]
    pub fn generate() -> Result<Self> {
        mushi::Identity::generate()
            .map(Self)
            .map_err(|e| err("identity", e))
    }

    /// The private key as PEM.
    #[napi(getter)]
    pub fn private_key_pem(&self) -> String {
        self.0.serialize_pem()
    }

    /// The public key as PEM.
    #[napi(getter)]
    pub fn public_key_pem(&self) -> String {
        self.0.public_key_pem()
    }

    /// Issue a certificate for this identity.
    ///
    /// `validitySeconds` must be under 14 days, or browsers will refuse the connection. Defaults to
    /// 13 days, which leaves room to rotate before expiry.
    ///
    /// The certificate carries no subject alternative names: a matching hash replaces certificate
    /// validation wholesale, names included, so the device can be reached on any address without
    /// reissuing.
    #[napi(ts_args_type = "validitySeconds?: number")]
    pub fn issue(&self, validity_seconds: Option<u32>) -> Result<Certificate> {
        let validity = match validity_seconds {
            Some(secs) => mushi::time::Duration::seconds(secs.into()),
            None => mushi::DEFAULT_VALIDITY,
        };

        self.0
            .issue(validity)
            .map(Certificate)
            .map_err(|e| err("certificate", e))
    }
}

/// A certificate issued from an `Identity`, along with the hash browsers pin it by.
#[napi]
#[derive(Debug, Clone)]
pub struct Certificate(mushi::Certificate);

#[napi]
impl Certificate {
    /// The hash to give the browser as `serverCertificateHashes`.
    ///
    /// ```js
    /// new WebTransport(url, {
    ///   serverCertificateHashes: [{ algorithm: cert.hashAlgorithm, value: cert.hash }],
    /// });
    /// ```
    #[napi(getter)]
    pub fn hash(&self) -> Buffer {
        Buffer::from(self.0.hash().value.as_slice())
    }

    /// The hash algorithm, in the spelling the browser API uses.
    #[napi(getter)]
    pub fn hash_algorithm(&self) -> String {
        self.0.hash().algorithm.to_owned()
    }

    /// The hash as lowercase hex, for publishing as text.
    #[napi(getter)]
    pub fn hash_hex(&self) -> String {
        self.0.hash().to_hex()
    }

    /// When the certificate becomes valid, in milliseconds since the Unix epoch.
    #[napi(getter)]
    pub fn not_before(&self) -> i64 {
        (self.0.not_before().unix_timestamp_nanos() / 1_000_000) as _
    }

    /// When the certificate expires, in milliseconds since the Unix epoch.
    ///
    /// Browsers refuse the connection past this point, so rotate before it arrives.
    #[napi(getter)]
    pub fn not_after(&self) -> i64 {
        (self.0.not_after().unix_timestamp_nanos() / 1_000_000) as _
    }

    /// Whether a browser could accept this certificate right now.
    #[napi(getter)]
    pub fn is_browser_valid(&self) -> bool {
        self.0.is_browser_valid()
    }
}

/// A Mushi server, accepting WebTransport sessions from browsers.
///
/// Unlike the Rust API, there's no need to install a CryptoProvider before using this.
#[napi]
#[derive(Debug, Clone)]
pub struct Server(mushi::Server);

#[napi]
impl Server {
    /// Create and bind a Mushi server.
    ///
    /// `bindTo` is a local or unspecified address. `[::]:0` binds every interface on a random port;
    /// use `localAddr` to find out which. `getaddrinfo()` or equivalent is used; to control DNS
    /// resolution, do that yourself and pass an IP address and port.
    ///
    /// `cc` is the congestion control strategy for the QUIC state machine. One of `cubic` ([RFC
    /// 8312]), `newreno` ([RFC 6582]), or `bbr` ([IETF Draft]). Defaults to `cubic`.
    ///
    /// [RFC 8312]: https://datatracker.ietf.org/doc/html/rfc8312
    /// [RFC 6582]: https://datatracker.ietf.org/doc/html/rfc6582
    /// [IETF Draft]: https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/02/
    #[napi(
        constructor,
        ts_args_type = "bindTo: string, cert: Certificate, cc?: string"
    )]
    pub fn new(bind_to: String, cert: &Certificate, cc: Option<String>) -> Result<Self> {
        let cc: Arc<dyn ControllerFactory + Send + Sync + 'static> =
            match cc.map(|s| s.to_ascii_lowercase()).as_deref() {
                Some("cubic") | None => Arc::new(CubicConfig::default()),
                Some("newreno") => Arc::new(NewRenoConfig::default()),
                Some("bbr") => Arc::new(BbrConfig::default()),
                Some(unk) => {
                    return Err(Error::from_reason(format!(
                        "unknown congestion control strategy {unk:?}",
                    )));
                }
            };

        let addr = bind_to
            .to_socket_addrs()
            .map_err(|e| err("bind", e))?
            .next()
            .ok_or_else(|| Error::from_reason(format!("{bind_to:?} resolved to no addresses")))?;

        mushi::Server::builder()
            .with_addr(addr)
            .with_congestion_control(cc)
            .with_certificate(cert.0.clone())
            .map(Self)
            .map_err(|e| err("server", e))
    }

    /// The local address the underlying socket is bound to.
    #[napi(getter)]
    pub fn local_addr(&self) -> Result<String> {
        self.0
            .local_addr()
            .map(|addr| addr.to_string())
            .map_err(|e| err("server", e))
    }

    /// The number of connections (≈sessions) currently open.
    #[napi(getter)]
    pub fn open_connections(&self) -> i64 {
        self.0.open_connections() as _
    }

    /// QUIC activity stats.
    #[napi(getter)]
    pub fn stats(&self) -> ServerStats {
        self.0.stats().into()
    }

    /// The certificate currently being served.
    #[napi(getter)]
    pub fn certificate(&self) -> Certificate {
        Certificate(self.0.certificate())
    }

    /// Replace the certificate served to new connections.
    ///
    /// Existing sessions are untouched. Publish the new hash *before* calling this, and keep
    /// publishing the old one until every browser has had a chance to pick up the change —
    /// `serverCertificateHashes` accepts a list precisely so the overlap is seamless.
    #[napi]
    pub fn set_certificate(&self, cert: &Certificate) -> Result<()> {
        self.0
            .set_certificate(cert.0.clone())
            .map_err(|e| err("server", e))
    }

    /// Wait for all sessions to be cleanly shut down.
    ///
    /// Waiting before exiting makes a good-faith effort to notify peers, where exiting immediately
    /// would force them to wait out the idle timeout. Does not close anything itself; call
    /// `server.close()` if that's what you want.
    #[napi]
    pub async fn wait_idle(&self) {
        self.0.wait_idle().await
    }

    /// Close all sessions immediately.
    ///
    /// Pending operations fail at once, and nothing is sent beyond a `CONNECTION_CLOSE` frame, so
    /// peers may drop data they had buffered. `reason` is truncated to fit a single packet, so keep
    /// it under 1KiB. See the notes on `session.close()`.
    #[napi]
    pub fn close(&self, code: u32, reason: String) {
        self.0.close(code, &reason)
    }

    /// Accept an incoming session request.
    ///
    /// The request is not yet a session: inspect it, then call `request.ok()` or
    /// `request.reject()`.
    ///
    /// Conceptually this is an async iterator that may throw at each call, and should be stopped
    /// once it returns `null`. A generator like this wraps it more ergonomically:
    ///
    /// ```js
    /// async function* accept(server) {
    ///     while (true) {
    ///         try {
    ///             const request = await server.accept();
    ///             if (!request) break; // server is closed
    ///             yield [null, request];
    ///         } catch (err) {
    ///             yield [err, null];
    ///         }
    ///     }
    /// }
    ///
    /// for await (const [err, request] of accept(server)) {
    ///     //
    /// }
    /// ```
    #[napi]
    pub async fn accept(&self) -> Option<Request> {
        self.0.accept().await.map(Request::new)
    }
}

/// Statistics on server activity.
#[napi(object)]
pub struct ServerStats {
    /// Cumulative number of QUIC handshakes accepted by this server.
    pub accepted_handshakes: i64,

    /// Cumulative number of QUIC handshakes sent from this server.
    pub outgoing_handshakes: i64,

    /// Cumulative number of QUIC handshakes refused by this server.
    pub refused_handshakes: i64,

    /// Cumulative number of QUIC handshakes ignored by this server.
    pub ignored_handshakes: i64,
}

impl From<mushi::quinn::EndpointStats> for ServerStats {
    fn from(inner: mushi::quinn::EndpointStats) -> Self {
        Self {
            accepted_handshakes: inner.accepted_handshakes as _,
            outgoing_handshakes: inner.outgoing_handshakes as _,
            refused_handshakes: inner.refused_handshakes as _,
            ignored_handshakes: inner.ignored_handshakes as _,
        }
    }
}

/// An incoming session, awaiting a decision.
///
/// This is where you route and authorise. The browser controls very little of the handshake: it
/// cannot set request headers, and WebTransport does not send cookies. In practice the **URL path
/// is the only channel it has**, so it carries both the protocol selection and any token you
/// authenticate with. The `origin` is set by the browser itself and is worth checking too.
///
/// `ok()`, `okWithProtocol()` and `reject()` each consume the request; calling a second one throws.
#[napi]
#[derive(Debug, Clone)]
pub struct Request {
    inner: Arc<Mutex<Option<mushi::Request>>>,
    url: String,
    path: String,
    origin: Option<String>,
    protocols: Vec<String>,
    remote_address: String,
}

impl Request {
    fn new(inner: mushi::Request) -> Self {
        Self {
            url: inner.url().to_string(),
            path: inner.path().to_owned(),
            origin: inner.origin().map(|o| o.to_owned()),
            protocols: inner.protocols().to_vec(),
            remote_address: inner.remote_address().to_string(),
            inner: Arc::new(Mutex::new(Some(inner))),
        }
    }

    async fn take(&self) -> Result<mushi::Request> {
        self.inner
            .lock()
            .await
            .take()
            .ok_or_else(|| Error::from_reason("request: already answered"))
    }
}

#[napi]
impl Request {
    /// The full URL the browser connected to.
    #[napi(getter)]
    pub fn url(&self) -> String {
        self.url.clone()
    }

    /// The path component of the URL.
    #[napi(getter)]
    pub fn path(&self) -> String {
        self.path.clone()
    }

    /// The `Origin` header, as set by the browser.
    ///
    /// Absent for non-browser clients, which can claim any origin they like — this identifies the
    /// page, and is not on its own an authentication.
    #[napi(getter)]
    pub fn origin(&self) -> Option<String> {
        self.origin.clone()
    }

    /// The subprotocols the client offered, in preference order.
    ///
    /// Not supported by every browser — Firefox doesn't implement subprotocol negotiation — so
    /// treat this as a hint and select on `path` instead.
    #[napi(getter)]
    pub fn protocols(&self) -> Vec<String> {
        self.protocols.clone()
    }

    /// The address the client is connecting from.
    #[napi(getter)]
    pub fn remote_address(&self) -> String {
        self.remote_address.clone()
    }

    /// Accept the session.
    #[napi]
    pub async fn ok(&self) -> Result<Session> {
        self.take()
            .await?
            .ok()
            .await
            .map(Session)
            .map_err(|e| err("request", e))
    }

    /// Accept the session, selecting one of the offered subprotocols.
    ///
    /// The protocol must be one the client offered. Clients that don't support negotiation ignore
    /// this.
    #[napi]
    pub async fn ok_with_protocol(&self, protocol: String) -> Result<Session> {
        self.take()
            .await?
            .ok_with_protocol(&protocol)
            .await
            .map(Session)
            .map_err(|e| err("request", e))
    }

    /// Reject the session with an HTTP status code.
    #[napi]
    pub async fn reject(&self, status: u16) -> Result<()> {
        let status = StatusCode::from_u16(status).map_err(|e| err("status", e))?;
        self.take()
            .await?
            .reject(status)
            .await
            .map_err(|e| err("request", e))
    }
}

/// A Session, able to accept/create streams and send/recv datagrams.
///
/// If all references to a session are dropped it closes with a `code` of 0 and an empty reason.
/// Close it explicitly with `session.close()` to say more.
#[napi]
#[derive(Debug, Clone)]
pub struct Session(mushi::Session);

#[napi]
impl Session {
    /// The subprotocol negotiated for this session, if any.
    #[napi(getter)]
    pub fn protocol(&self) -> Option<String> {
        self.0.protocol().map(|p| p.to_owned())
    }

    /// The maximum size of a datagram that can be sent.
    #[napi(getter)]
    pub fn max_datagram_size(&self) -> i64 {
        self.0.max_datagram_size() as _
    }

    /// Wait until the peer creates a new unidirectional stream.
    ///
    /// Will error if the session has been closed.
    #[napi]
    pub async fn accept_uni(&self) -> Result<RecvStream> {
        self.0
            .accept_uni()
            .await
            .map(RecvStream::new)
            .map_err(|e| err("session", e))
    }

    /// Wait until the peer creates a new bidirectional stream.
    #[napi]
    pub async fn accept_bi(&self) -> Result<BidiStream> {
        self.0
            .accept_bi()
            .await
            .map(BidiStream::new)
            .map_err(|e| err("session", e))
    }

    /// Open a new bidirectional stream.
    ///
    /// May wait when there are too many concurrent streams.
    #[napi]
    pub async fn open_bi(&self) -> Result<BidiStream> {
        self.0
            .open_bi()
            .await
            .map(BidiStream::new)
            .map_err(|e| err("session", e))
    }

    /// Open a new unidirectional stream.
    ///
    /// May wait when there are too many concurrent streams. Note that WebTransport is symmetric
    /// once established: the server can push to the browser without being asked.
    #[napi]
    pub async fn open_uni(&self) -> Result<SendStream> {
        self.0
            .open_uni()
            .await
            .map(SendStream::new)
            .map_err(|e| err("session", e))
    }

    /// Send an unreliable datagram over the network.
    ///
    /// QUIC datagrams may be dropped for any reason, including (non-exhaustive):
    ///
    /// - Network congestion
    /// - Random packet loss
    /// - Payload is larger than `maxDatagramSize`
    /// - Peer is not receiving datagrams
    /// - Peer has too many outstanding datagrams
    #[napi]
    pub fn send_datagram(&self, payload: Buffer) -> Result<()> {
        self.0
            .send_datagram(bytes::Bytes::from_owner(payload))
            .map_err(|e| err("session", e))
    }

    /// Receive a datagram over the network.
    #[napi]
    pub async fn recv_datagram(&self) -> Result<Buffer> {
        self.0
            .recv_datagram()
            .await
            .map(|b| Buffer::from(&*b))
            .map_err(|e| err("session", e))
    }

    /// Close the session immediately.
    ///
    /// Pending operations fail at once. Nothing is sent beyond a `CONNECTION_CLOSE` frame, and the
    /// peer may drop stream data it hasn't yet handed to its application — including data it
    /// already acknowledged. `reason` is truncated to fit a single packet, so keep it under 1KiB.
    ///
    /// Only the peer that received data last can know it all arrived. To close gracefully, have
    /// that side call this, and give the frame time to arrive with `server.waitIdle()`; otherwise
    /// the peer times the session out after 30 seconds.
    #[napi]
    pub fn close(&self, code: u32, reason: String) {
        self.0.close(code, &reason)
    }

    /// Wait until the session is closed, and return why as a string.
    #[napi]
    pub async fn closed(&self) -> String {
        self.0.closed().await.to_string()
    }
}

// SAFETY notes: it's unsound to use a &mut self async function from JS if there's a possibility of
// the JS side changing the Rust-observed data across an await point. However, that's not the case
// here as the internals of RecvStream and SendStream are opaque to JS, and cannot be changed
// there. There remains a risk if the JS calls the methods several times concurrently, which could
// appear as "multiple &mut accesses". For this reason, the streams are further protected by a
// Mutex. In the general case (single accesses) this will add a little overhead but no contention.

/// A handle to a QUIC receive stream.
///
/// It's important to never call methods on this object concurrently, ie not to do two reads, or to
/// call `stop()` while reading the stream in an overlapping async context. The stream has an
/// internal mutex (lock), and overlapping accesses will introduce undesirable contention.
#[napi]
#[derive(Debug, Clone)]
pub struct RecvStream(Arc<Mutex<mushi::RecvStream>>);

#[napi]
impl RecvStream {
    fn new(s: mushi::RecvStream) -> Self {
        Self(Arc::new(Mutex::new(s)))
    }

    /// Read the next chunk of data with the provided maximum size.
    ///
    /// Returns `null` if there's nothing more to read (the stream is finished).
    #[napi]
    pub async fn read(&self, max: i64) -> Result<Option<Buffer>> {
        self.0
            .lock()
            .await
            .read(max as _)
            .await
            .map(|b| b.map(|bytes| Buffer::from(&*bytes)))
            .map_err(|e| err("recv", e))
    }

    /// Read some data into the provided buffer.
    ///
    /// Returns the number of bytes read, or `null` if the stream is finished. Make sure to
    /// differentiate between `0` and `null`.
    #[napi]
    pub async fn read_buf(&self, mut buf: Buffer) -> Result<Option<i64>> {
        self.0
            .lock()
            .await
            .read_buf(&mut buf.as_mut())
            .await
            .map(|b| b.map(|bytes| bytes as _))
            .map_err(|e| err("recv", e))
    }

    /// Send a `STOP_SENDING` QUIC code, asking the peer to stop writing.
    #[napi]
    pub async fn stop(&self, code: u32) {
        self.0.lock().await.stop(code);
    }
}

/// A handle to a QUIC send stream.
///
/// It's important to never call methods on this object concurrently, ie not to do two writes, or
/// to call `setPriority()` while writing to the stream in an overlapping async context. The stream
/// has an internal mutex (lock), and overlapping accesses will introduce undesirable contention.
#[napi]
#[derive(Debug, Clone)]
pub struct SendStream(Arc<Mutex<mushi::SendStream>>);

#[napi]
impl SendStream {
    fn new(s: mushi::SendStream) -> Self {
        Self(Arc::new(Mutex::new(s)))
    }

    /// Write the entire buffer to the stream.
    #[napi]
    pub async fn write(&self, buf: Buffer) -> Result<()> {
        self.0
            .lock()
            .await
            .write(&buf)
            .await
            .map_err(|e| err("send", e))
    }

    /// Finish the stream cleanly, signalling there's nothing more to send.
    #[napi]
    pub async fn finish(&self) -> Result<()> {
        self.0.lock().await.finish().map_err(|e| err("send", e))
    }

    /// Set the stream's priority.
    ///
    /// Streams with lower values will be sent first, but are not guaranteed to arrive first.
    #[napi]
    pub async fn set_priority(&self, order: i32) {
        self.0.lock().await.set_priority(order);
    }

    /// Send an immediate reset code, closing the stream.
    #[napi]
    pub async fn reset(&self, code: u32) {
        self.0.lock().await.reset(code);
    }
}

/// Return value of `acceptBi()` and `openBi()`.
///
/// This can be used to obtain (once) the recv and send streams.
#[napi]
#[derive(Debug)]
pub struct BidiStream {
    recv: Option<RecvStream>,
    send: Option<SendStream>,
}

impl BidiStream {
    fn new((s, r): (mushi::SendStream, mushi::RecvStream)) -> Self {
        Self {
            send: Some(SendStream::new(s)),
            recv: Some(RecvStream::new(r)),
        }
    }
}

#[napi]
impl BidiStream {
    /// Obtain the recv stream.
    ///
    /// May only be called once. After that, it will return null.
    #[napi]
    pub fn take_recv(&mut self) -> Option<RecvStream> {
        self.recv.take()
    }

    /// Obtain the send stream.
    ///
    /// May only be called once. After that, it will return null.
    #[napi]
    pub fn take_send(&mut self) -> Option<SendStream> {
        self.send.take()
    }
}

/// How long, in milliseconds, until the certificate expires.
///
/// Negative once it has. Useful for scheduling rotation.
#[napi]
pub fn millis_until_expiry(cert: &Certificate) -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as i64;
    cert.not_after() - now
}
