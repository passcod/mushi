use std::{
    fmt,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use mushi::{
    AllowConnection, CertificateError, SigScheme, SubjectPublicKeyInfoDer,
    quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig},
    rcgen,
};
use napi::{
    bindgen_prelude::*,
    threadsafe_function::{ErrorStrategy, ThreadsafeFunction, ThreadsafeFunctionCallMode},
};
use napi_derive::*;
use tokio::sync::Mutex;

static SETUP: LazyLock<()> = LazyLock::new(mushi::install_crypto_provider);

const SUPPORTED_SIGSCHEMES: &[SigScheme] = &[
    mushi::SIGSCHEME_ED25519,
    mushi::SIGSCHEME_ECDSA256,
    mushi::SIGSCHEME_ECDSA384,
];

/// A key pair that identifies and authenticates an `Endpoint`.
#[napi]
#[derive(Debug, Clone)]
pub struct EndpointKey(mushi::EndpointKey);

#[napi]
impl EndpointKey {
    /// Load a private key from a PEM-encoded PKCS#8 private key string.
    ///
    /// If the key is not ED25519 or ECDSA(256|384), this will error.
    #[napi(constructor)]
    pub fn new(private_key_pem: String) -> Result<Self> {
        let kp = rcgen::KeyPair::from_pem(&private_key_pem)
            .map_err(|err| Error::from_reason(format!("pem: {err}")))?;

        for scheme in SUPPORTED_SIGSCHEMES {
            if kp.is_compatible(scheme.1) {
                return Ok(Self(mushi::EndpointKey::load(kp, *scheme)));
            }
        }

        Err(Error::from_reason(format!(
            "private key is {:?}, which is not a supported type",
            kp.algorithm()
        )))
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

    /// Generate a new random key pair in the default scheme.
    #[napi]
    pub fn generate() -> Result<Self> {
        mushi::EndpointKey::generate()
            .map(Self)
            .map_err(|err| Error::from_reason(err.to_string()))
    }

    /// Generate a new random key pair in the given scheme.
    ///
    /// The argument must be one of `ed25519`, `ecdsa256`, `ecdsa384`.
    #[napi]
    pub fn generate_for(scheme: String) -> Result<Self> {
        let scheme = match scheme.as_str() {
            "ed25519" => mushi::SIGSCHEME_ED25519,
            "ecdsa256" => mushi::SIGSCHEME_ECDSA256,
            "ecdsa384" => mushi::SIGSCHEME_ECDSA384,
            unk => {
                return Err(Error::from_reason(format!(
                    "{unk} is not a supported scheme"
                )));
            }
        };

        mushi::EndpointKey::generate_for(scheme)
            .map(Self)
            .map_err(|err| Error::from_reason(err.to_string()))
    }

    /// The validity of certificates generated by this key in seconds.
    #[napi(getter)]
    pub fn validity(&self) -> u32 {
        self.0.validity.whole_seconds().max(0).try_into().unwrap()
    }

    /// Set the validity of certificates generated by this key in seconds.
    ///
    /// Note that changing the validity of a key once it's used in an Endpoint does nothing.
    #[napi(setter, js_name = "validity")]
    pub fn set_validity(&mut self, seconds: u32) {
        self.0.validity = Duration::from_secs(seconds as _).try_into().unwrap();
    }

    /// Generate a certificate for this key.
    ///
    /// This is primarily used internally, but exposed for convenience if you're implementing the
    /// transport yourself and don't want to bother making certificates correctly.
    ///
    /// Returns the PEM-encoded certificate.
    #[napi]
    pub fn make_certificate(&self) -> Result<String> {
        self.0
            .make_certificate()
            .map_err(|err| Error::from_reason(format!("key: {err}")))
            .map(|c| c.pem())
    }
}

/// Trust policy for peers.
#[napi]
#[derive(Debug)]
pub struct Allower(Arc<AllowerImpl>);

pub struct AllowerImpl {
    allower: ThreadsafeFunction<(Buffer,), ErrorStrategy::Fatal>,
    client_auth: bool,
}

impl fmt::Debug for AllowerImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let allower = f
            .debug_struct("ThreadsafeFunction")
            .finish_non_exhaustive()?;
        f.debug_struct("Allower")
            .field("allower", &allower)
            .field("client_auth", &self.client_auth)
            .finish()
    }
}

impl AllowConnection for AllowerImpl {
    fn allow_public_key(
        &self,
        key: SubjectPublicKeyInfoDer<'_>,
    ) -> std::result::Result<(), CertificateError> {
        use std::sync::{Arc, Condvar, Mutex};
        let sync = Arc::new((Mutex::new(false), Condvar::new(), AtomicBool::new(false)));

        let status = self.allower.call_with_return_value(
            (Buffer::from(&*key),),
            ThreadsafeFunctionCallMode::Blocking,
            {
                let sync = Arc::clone(&sync);
                move |value: bool| {
                    let (lock, cvar, ret) = &*sync;
                    let mut done = lock.lock().unwrap();
                    ret.store(value, Ordering::SeqCst);
                    *done = true;
                    cvar.notify_one();
                    Ok(())
                }
            },
        );

        let (lock, cvar, ret) = &*sync;
        if status == Status::Ok {
            let mut done = lock.lock().unwrap();
            while !*done {
                done = cvar.wait(done).unwrap();
            }
        }

        if ret.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(CertificateError::ApplicationVerificationFailure)
        }
    }

    fn require_client_auth(&self) -> bool {
        self.client_auth
    }
}

#[napi]
impl Allower {
    /// Define a new peer trust policy.
    ///
    /// `key` is the public key of the remote peer in DER format, but in general should be
    /// considered an opaque blob.
    ///
    /// `now` is a Unix timestamp (number of non-leap seconds since the epoch). If your trust logic
    /// involves time, you should use this as basis time to make calculations consistent.
    ///
    /// Return `true` to allow the peer to connect (or be connected to).
    ///
    /// `requireClientAuth` can be set to `false` for the rare case where incoming connections that
    /// cannot present a client certificate should be allowed. In that case, take care to implement
    /// an additional authorisation layer to restrict connections or resource access.
    #[napi(
        constructor,
        ts_args_type = "allowPublicKey: (key: Buffer) => boolean, requireClientAuth?: boolean"
    )]
    pub fn new(
        allow_public_key: ThreadsafeFunction<(Buffer,), ErrorStrategy::Fatal>,
        require_client_auth: Option<bool>,
    ) -> Self {
        let require_client_auth = require_client_auth.unwrap_or(true);
        Self(Arc::new(AllowerImpl {
            allower: allow_public_key,
            client_auth: require_client_auth,
        }))
    }
}

/// The main entrypoint to create connections to, and accept connections from other Mushi peers.
///
/// Generally, an application will have a single endpoint instance. This results in more optimal
/// network behaviour, and as a single endpoint can have sessions to any number of peers, and each
/// session supports many concurrent datagrams and streams, there’s little need (outside of
/// testing) for multiple endpoints.
///
/// Note that unlike the Rust API, there's no need to install a CryptoProvider before using this.
#[napi]
#[derive(Debug, Clone)]
pub struct Endpoint(mushi::Endpoint);

#[napi]
impl Endpoint {
    /// Create and setup a Mushi peer.
    ///
    /// You must provide a local or unspecified address to bind the endpoint to. In most cases,
    /// `[::]:0` suffices: this binds to all IP interfaces and selects a random port. Use
    /// `localAddr()` to discover the randomly-assigned port.
    ///
    /// If `bind_to` resolves to multiple socket addresses, the first that succeeds creation of the
    /// socket will be used. `getaddrinfo()` or equivalent is used; to control DNS resolution, do
    /// that yourself and pass an IP address and port.
    ///
    /// `allower` is the trust policy for remote peers: incoming (client certificate) and outgoing
    /// (server certificate) peers will have their public key extracted and checked by the
    /// `Allower` instance.
    ///
    /// `cc` is the congestion control strategy for the QUIC state machine. One of `cubic` ([RFC
    /// 8312]), `newreno` ([RFC 6582]), or `bbr` ([IETF Draft]]. Defaults to `cubic`.
    ///
    /// [RFC 8312]: https://datatracker.ietf.org/doc/html/rfc8312
    /// [RFC 6582]: https://datatracker.ietf.org/doc/html/rfc6582
    /// [IETF Draft]: https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/02/
    #[napi(
        constructor,
        ts_args_type = "bindTo: string, key: EndpointKey, allower: Allower, cc?: string"
    )]
    pub fn new(
        bind_to: String,
        key: &EndpointKey,
        allower: &Allower,
        cc: Option<String>,
    ) -> Result<Self> {
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

        *SETUP;

        mushi::Endpoint::new(bind_to, key.0.clone(), allower.0.clone(), Some(cc))
            .map(Self)
            .map_err(|err| Error::from_reason(format!("endpoint: {err}")))
    }

    /// The local address the underlying socket is bound to.
    #[napi(getter)]
    pub fn local_addr(&self) -> Result<String> {
        self.0
            .local_addr()
            .map(|addr| addr.to_string())
            .map_err(|err| Error::from_reason(format!("endpoint: {err}")))
    }

    /// The number of connections (≈sessions) that are currently open.
    #[napi(getter)]
    pub fn open_connections(&self) -> i64 {
        self.0.open_connections() as _
    }

    /// QUIC activity stats.
    #[napi(getter)]
    pub fn stats(&self) -> EndpointStats {
        self.0.stats().into()
    }

    /// Wait for all sessions on the endpoint to be cleanly shut down.
    ///
    /// Waiting for this condition before exiting ensures that a good-faith effort is made to
    /// notify peers of recent session closes, whereas exiting immediately could force them to wait
    /// out the idle timeout period.
    ///
    /// Does not proactively close existing sessions or cause incoming sessions to be rejected.
    /// Consider calling `session.close()` if that is desired.
    #[napi]
    pub async fn wait_idle(&self) {
        self.0.wait_idle().await
    }

    /// Connect to a peer.
    #[napi]
    pub async fn connect(&self, addrs: String) -> Result<Session> {
        self.0
            .connect(addrs)
            .await
            .map_err(|err| Error::from_reason(format!("endpoint: {err}")))
            .map(Session)
    }

    /// Accept an incoming session.
    ///
    /// Using this is a bit un-JS-y. Conceptually, it's an async iterator which may throw at each
    /// call, and should be stopped once the function successfully returns `null`. A generator like
    /// this may be used to wrap the call more ergonomically:
    ///
    /// ```js
    /// async function* accept() {
    ///     while (true) {
    ///         try {
    ///             const session = await endpoint.accept();
    ///             if (!session) break; // endpoint is closed
    ///             yield [null, session];
    ///         } catch (err) {
    ///             yield [err, null];
    ///         }
    ///     }
    /// }
    ///
    /// for await (const [err, session] of accept()) {
    ///     //
    /// }
    /// ```
    #[napi]
    pub async fn accept(&self) -> Result<Option<Session>> {
        self.0
            .accept()
            .await
            .transpose()
            .map_err(|err| Error::from_reason(format!("endpoint: {err}")))
            .map(|os| os.map(Session))
    }
}

/// Statistics on Endpoint activity.
#[napi(object)]
pub struct EndpointStats {
    /// Cumulative number of QUIC handshakes accepted by this Endpoint.
    pub accepted_handshakes: i64,

    /// Cumulative number of QUIC handshakees sent from this Endpoint.
    pub outgoing_handshakes: i64,

    /// Cumulative number of QUIC handshakes refused on this Endpoint.
    pub refused_handshakes: i64,

    /// Cumulative number of QUIC handshakes ignored on this Endpoint.
    pub ignored_handshakes: i64,
}

impl From<mushi::quinn::EndpointStats> for EndpointStats {
    fn from(inner: mushi::quinn::EndpointStats) -> Self {
        Self {
            accepted_handshakes: inner.accepted_handshakes as _,
            outgoing_handshakes: inner.outgoing_handshakes as _,
            refused_handshakes: inner.refused_handshakes as _,
            ignored_handshakes: inner.ignored_handshakes as _,
        }
    }
}

/// A Session, able to accept/create streams and send/recv datagrams.
///
/// If all references to a session have been dropped, then the session will be automatically
/// closed with a `code` of 0 and an empty reason. You can also close the session explicitly by
/// calling `session.close()`.
///
/// Closing the session immediately sends a `CONNECTION_CLOSE` frame and then abandons efforts to
/// deliver data to the peer. Upon receiving a `CONNECTION_CLOSE` frame, the peer may drop any
/// stream data not yet delivered to the application. `session.close()` describes in more detail
/// how to gracefully close a session without losing application data.
#[napi]
#[derive(Debug, Clone)]
pub struct Session(mushi::Session);

#[napi]
impl Session {
    /// The public key of the remote peer.
    ///
    /// This may be unavailable if `requireClientAuth` was set to `false` in the `Allower`.
    #[napi]
    pub fn peer_key(&self) -> Option<Buffer> {
        self.0.peer_key().map(|k| (**k).into())
    }

    /// The maximum size of a datagram that can be sent.
    #[napi]
    pub async fn max_datagram_size(&self) -> i64 {
        self.0.max_datagram_size().await as _
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
            .map_err(|err| Error::from_reason(format!("session: {err}")))
    }

    /// Wait until the peer creates a new bidirectional stream.
    #[napi]
    pub async fn accept_bi(&self) -> Result<BidiStream> {
        self.0
            .accept_bi()
            .await
            .map(|(s, r)| BidiStream {
                send: Some(SendStream::new(s)),
                recv: Some(RecvStream::new(r)),
            })
            .map_err(|err| Error::from_reason(format!("session: {err}")))
    }

    /// Open a new bidirectional stream.
    ///
    /// May wait when there are too many concurrent streams.
    #[napi]
    pub async fn open_bi(&self) -> Result<BidiStream> {
        self.0
            .open_bi()
            .await
            .map(|(s, r)| BidiStream {
                send: Some(SendStream::new(s)),
                recv: Some(RecvStream::new(r)),
            })
            .map_err(|err| Error::from_reason(format!("session: {err}")))
    }

    /// Open a new unidirectional stream.
    ///
    /// May wait when there are too many concurrent streams.
    #[napi]
    pub async fn open_uni(&self) -> Result<SendStream> {
        self.0
            .open_uni()
            .await
            .map(SendStream::new)
            .map_err(|err| Error::from_reason(format!("session: {err}")))
    }

    /// Send an unreliable datagram over the network.
    ///
    /// QUIC datagrams may be dropped for any reason, including (non-exhaustive):
    ///
    /// - Network congestion
    /// - Random packet loss
    /// - Payload is larger than `max_datagram_size()`
    /// - Peer is not receiving datagrams
    /// - Peer has too many outstanding datagrams
    #[napi]
    pub fn send_datagram(&self, payload: Buffer) -> Result<()> {
        self.0
            .send_datagram(bytes::Bytes::from_owner(payload))
            .map_err(|err| Error::from_reason(format!("session: {err}")))
    }

    /// Receive a datagram over the network.
    #[napi]
    pub async fn recv_datagram(&self) -> Result<Buffer> {
        self.0
            .recv_datagram()
            .await
            .map(|b| Buffer::from(&*b))
            .map_err(|err| Error::from_reason(format!("session: {err}")))
    }

    /// Close the session immediately.
    ///
    /// Pending operations will fail immediately with a `LocallyClosed` error. No more data is sent
    /// to the peer beyond a `CONNECTION_CLOSE` frame, and the peer may drop buffered data upon
    /// receiving the `CONNECTION_CLOSE` frame.
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
    /// both endpoints stay online long enough, and `endpoint.wait_idle()` can be used to provide
    /// sufficient time. Otherwise, the remote peer will time out the session after 30 seconds.
    ///
    /// The sending side can not guarantee all stream data is delivered to the remote application.
    ///
    /// It only knows the data is delivered to the QUIC stack of the remote endpoint. Once the
    /// local side sends a `CONNECTION_CLOSE` frame, the remote endpoint may drop any data it
    /// received but is as yet undelivered to the application, including data that was acknowledged
    /// as received to the local endpoint.
    #[napi]
    pub fn close(&self, code: i32, reason: String) {
        self.0.close(code as _, &reason)
    }

    /// Wait until the connection is closed.
    ///
    /// Returns `null` if the connection was closed locally, and a string if the connection
    /// was closed by a peer (e.g. with `close()`). Throws for other unexpected close reasons.
    #[napi]
    pub async fn closed(&self) -> Result<Option<String>> {
        self.0
            .closed()
            .await
            .map(|r| r.map(|reason| reason.to_string()))
            .map_err(|err| Error::from_reason(format!("session: {err}")))
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
    /// Returns `null` if there's nothing more to read (the stream is closed).
    #[napi]
    pub async fn read(&self, max: i64) -> Result<Option<Buffer>> {
        self.0
            .lock()
            .await
            .read(max as _)
            .await
            .map(|b| b.map(|bytes| Buffer::from(&*bytes)))
            .map_err(|err| Error::from_reason(format!("recv: {err}")))
    }

    /// Read some data into the provided buffer.
    ///
    /// Returns the number of bytes read, or `null` if the stream is closed.
    /// Make sure to differentiate between `0` and `null`.
    #[napi]
    pub async fn read_buf(&self, mut buf: Buffer) -> Result<Option<i64>> {
        self.0
            .lock()
            .await
            .read_buf(&mut buf.as_mut())
            .await
            .map(|b| b.map(|bytes| bytes as _))
            .map_err(|err| Error::from_reason(format!("recv: {err}")))
    }

    /// Send a `STOP_SENDING` QUIC code.
    #[napi]
    pub async fn stop(&self, code: i32) {
        self.0.lock().await.stop(code as _);
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
            .write(&*buf)
            .await
            .map_err(|err| Error::from_reason(format!("send: {err}")))
    }

    /// Set the stream’s priority.
    ///
    /// Streams with lower values will be sent first, but are not guaranteed to arrive first.
    pub async fn set_priority(&self, order: i32) {
        self.0.lock().await.set_priority(order);
    }

    /// Send an immediate reset code, closing the stream.
    pub async fn reset(&self, code: i32) {
        self.0.lock().await.reset(code as _);
    }
}

/// Return value of `accept_bi()` and `open_bi()`.
///
/// This can be used to obtain (once) the recv and send streams.
#[napi]
#[derive(Debug)]
pub struct BidiStream {
    recv: Option<RecvStream>,
    send: Option<SendStream>,
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
