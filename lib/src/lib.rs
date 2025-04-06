//! Mushi is point-to-point QUIC networking with application-defined mutual authentication.
//!
//! It takes inspiration from [Iroh](https://iroh.computer) and its APIs are based on
//! [WebTransport](https://developer.mozilla.org/en-US/docs/Web/API/WebTransport).
//!
//! In Mushi, peers are identified by a persistent key pair (ECDSA or ED25519). Connecting to peers
//! is done by DNS or IP addresses (it doesn't have peer discovery or NAT traversal). Endpoints
//! define a trust policy, which is given a public key (which may be considered an opaque binary
//! blob). Endpoints handle both outgoing (client) and incoming (server) function: typically, a
//! single [Endpoint] is started per application. Connecting to (or accepting an incoming
//! connection from) another peer creates a [Session], which supports sending and receiving
//! unreliable datagrams as well as multiple concurrent unidirectional and bidirectional streams.
//!
//! All communications are secured with TLS 1.3, with RSA suites explicitly disabled. Endpoints
//! have a key pair (which may be generated on startup), and each connection uses a unique
//! just-in-time short-lived certificate (valid for 2 minute — TODO: validity not checked now).
//!
//! This provides authentication: peers are guaranteed to have control over their own key pair, and
//! it's unfeasible for an attacker in possession of a public key to obtain the associate private
//! key to be able to successfully spoof an endpoint.
//!
//! However, it does not provide authorisation. Mushi applications should implement this with one
//! or two layers: the [`AllowConnection`] trait provides an application with a simple peer trust
//! policy ("should we allow this peer to connect or be connected to"), and application-specific
//! schemes layered on top of connections. This latter layer is not provided nor facilitated by
//! Mushi (except to the extent that an established session can retrieve its remote peer's public
//! key using [`Session::peer_key()`]): it is the responsibility of application implementers to
//! decide whether authorisation beyond peer public key trust is required, and how to do it.
//!
//! Mushi does not at present implement ECH (Encrypted Client Hello). This may be added in the
//! future; it would require providing the public key of the remote peer upfront.
//!
//! # Example
//!
//! ```ignore
//! use mushi::{AllowAllConnections, Endpoint, EndpointKey, Session};
//!
//! #[tokio::main]
//! async fn main() {
//!     mushi::install_crypto_provider();
//!
//!     let key = EndpointKey::generate().unwrap();
//!     let policy = Arc::new(AllowAllConnections);
//!     let end = Endpoint::new("[::]:0", key, policy, None).unwrap();
//!
//!     let mut session = end.connect("remotepeer.example.com:1310").await.unwrap();
//!     session.send_datagram("Hello world".into()).unwrap();
//!
//!     let (mut s, mut r) = session.open_bi().await.unwrap();
//!     s.write(b"How are you today?").await.unwrap();
//!     let response = r.read(1024).await.unwrap();
//!     println!("peer said: {response:x?}");
//! }
//! ```
#![warn(missing_docs)]

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};

pub use crate::{key::*, provider::install_crypto_provider};
pub use rcgen;
pub use rustls::{CertificateError, pki_types::SubjectPublicKeyInfoDer};
pub use url::Url;
pub use web_transport_quinn::{self as web_transport, quinn, quinn::rustls};

use bytes::{Buf, BufMut, Bytes};
use quinn::{
    ApplicationClose, ConnectionError,
    congestion::ControllerFactory,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rcgen::KeyPair;
use rustls::{
    DigitallySignedStruct, DistinguishedName, KeyLogFile, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::{
        ParsedCertificate,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use tokio::sync::Mutex;
use web_transport::{ALPN, SessionError};

mod key;
mod provider;

/// Options for an [Endpoint].
#[derive(Clone)]
pub struct EndpointOptions {
    /// Whether incoming peers need to provide a certificate.
    ///
    /// This is `true` by default, and is the expectation in Mushi applications. In certain
    /// use-cases, allowing "anonymous" clients may be necessary; take care to implement your own
    /// authorisation layer as required.
    pub require_client_auth: bool,

    /// Whether validity periods are checked.
    ///
    /// This is `false` by default: keys are just-in-time and all that really matter, and validity
    /// periods are a polite fiction to make the TLS look normal. It might be useful for hardening
    /// to enable this; this will also require that the system clocks within the distributed
    /// system are synchronised to within the validity period (±1 minute by default).
    ///
    /// TODO: this is not yet implemented, setting `true` will panic.
    pub check_validity_period: bool,

    /// The congestion control strategy for the QUIC state machine.
    ///
    /// You can select different strategies from [`quinn::congestion`] or elsewhere to optimise for
    /// throughput or latency. The default strategy is Cubic, aka RFC 8312 (TCP's algorithm).
    pub congestion_control: Arc<(dyn ControllerFactory + Send + Sync + 'static)>,

    /// A global keys trust policy.
    ///
    /// This is checked before any peer is allowed to connect or be connected to, early in the
    /// handshake process, before any link information is available. You may use this as an
    /// additional security layer, or for efficiency to drop unauthorised peers early.
    ///
    /// Return `Ok(())` to allow the peer identified by the key, and `Err(_)` to reject the peer.
    /// You should select an appropriate [`CertificateError`]; if in doubt, use
    /// [`ApplicationVerificationFailure`](CertificateError::ApplicationVerificationFailure).
    ///
    /// By default all keys are allowed (i.e. peers are checked at link establishment only).
    #[allow(clippy::type_complexity)]
    pub key_trust_policy: Arc<
        dyn (Fn(SubjectPublicKeyInfoDer<'_>) -> Result<(), CertificateError>)
            + Send
            + Sync
            + 'static,
    >,
}

impl fmt::Debug for EndpointOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointOptions")
            .field("require_client_auth", &self.require_client_auth)
            .field("check_validity_period", &self.check_validity_period)
            .finish_non_exhaustive()
    }
}

impl Default for EndpointOptions {
    fn default() -> Self {
        Self {
            require_client_auth: true,
            check_validity_period: false,
            congestion_control: Arc::new(quinn::congestion::CubicConfig::default()),
            key_trust_policy: Arc::new(|_| Ok(())),
        }
    }
}

impl ServerCertVerifier for EndpointOptions {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;

        if self.check_validity_period {
            todo!("check_validity_period");
        }

        (self.key_trust_policy)(cert.subject_public_key_info())
            .map_err(rustls::Error::from)
            .and(Ok(ServerCertVerified::assertion()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        unimplemented!("mushi works exclusively over TLS 1.3")
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algos = CryptoProvider::get_default()
            .expect("a default CryptoProvider must be set")
            .signature_verification_algorithms;
        verify_tls13_signature(message, cert, dss, &algos)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        CryptoProvider::get_default()
            .expect("a default CryptoProvider must be set")
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ClientCertVerifier for EndpointOptions {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;

        if self.check_validity_period {
            todo!("check_validity_period");
        }

        (self.key_trust_policy)(cert.subject_public_key_info())
            .map_err(rustls::Error::from)
            .and(Ok(ClientCertVerified::assertion()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        unimplemented!("mushi works exclusively over TLS 1.3")
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algos = CryptoProvider::get_default()
            .expect("a default CryptoProvider must be set")
            .signature_verification_algorithms;
        verify_tls13_signature(message, cert, dss, &algos)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        CryptoProvider::get_default()
            .expect("a default CryptoProvider must be set")
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.require_client_auth
    }
}

/// The main entrypoint to create connections to, and accept connections from other Mushi peers.
///
/// Generally, an application will have a single endpoint instance. This results in more optimal
/// network behaviour, and as a single endpoint can many independent links to any number of peers,
/// there's little need (outside of testing) for multiple endpoints.
///
/// Before creating an endpoint, ensure that a default [`rustls::crypto::CryptoProvider`] has been
/// installed, preferably using [`install_crypto_provider()`].
#[derive(Clone)]
pub struct Endpoint {
    options: Arc<EndpointOptions>,
    client_config: quinn::ClientConfig,
    server: Arc<Mutex<web_transport::Server>>,
    key: Arc<Key>,
    endpoint: quinn::Endpoint,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let server = &f
            .debug_struct("web_transport_quinn::Server")
            .finish_non_exhaustive()?;
        f.debug_struct("Endpoint")
            .field("options", &self.options)
            .field("client_config", &self.client_config)
            .field("server", &server)
            .field("key", &self.key)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl Endpoint {
    /// Create and setup a Mushi peer.
    ///
    /// You must provide a local or unspecified address to bind the endpoint to. In most cases,
    /// `"[::]:0"` suffices: this binds to all IP interfaces and selects a random port. Use
    /// [`Endpoint::local_addr()`] to discover the randomly-assigned port.
    ///
    /// If `bind_to` resolves to multiple socket addresses, the first that succeeds creation of the
    /// socket will be used.
    ///
    /// Requires a Tokio runtime, even though the function is not async.
    pub fn new(
        bind_to: impl ToSocketAddrs,
        key: Key,
        options: EndpointOptions,
    ) -> Result<Self, Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = Arc::new(key);
        let options = Arc::new(options);

        let mut server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(options.clone())
            .with_cert_resolver(key.clone());
        server_config.alpn_protocols = vec![ALPN.to_vec()];

        let mut client_config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(options.clone())
            .with_client_cert_resolver(key.clone());
        client_config.alpn_protocols = vec![ALPN.to_vec()];

        if cfg!(debug_assertions) {
            server_config.key_log = Arc::new(KeyLogFile::new());
            client_config.key_log = server_config.key_log.clone();
        }

        let mut transport = quinn::TransportConfig::default();
        transport.congestion_controller_factory(options.congestion_control.clone());
        let transport = Arc::new(transport);

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_config).unwrap(),
        ));
        server_config.transport_config(transport.clone());

        let mut client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_config).unwrap()));
        client_config.transport_config(transport);

        let mut last_err = None;
        let mut endpoint = None;
        for addr in bind_to.to_socket_addrs()? {
            match quinn::Endpoint::server(server_config.clone(), addr) {
                Ok(s) => {
                    endpoint = Some(s);
                    break;
                }
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }
        let mut endpoint = match (endpoint, last_err) {
            (Some(e), _) => e,
            (None, Some(err)) => return Err(err.into()),
            (None, None) => return Err(Error::NoAddrs),
        };
        endpoint.set_default_client_config(client_config.clone());

        Ok(Self {
            options,
            key,
            client_config,
            server: Arc::new(Mutex::new(web_transport::Server::new(endpoint.clone()))),
            endpoint,
        })
    }

    /// Get the local address the underlying socket is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.endpoint.local_addr().map_err(Error::from)
    }

    /// Get the number of connections (≈sessions) that are currently open.
    pub fn open_connections(&self) -> usize {
        self.endpoint.open_connections()
    }

    /// Get QUIC activity stats.
    pub fn stats(&self) -> quinn::EndpointStats {
        self.endpoint.stats()
    }

    /// Connect to a peer.
    ///
    /// If `addrs` contains unspecified addresses (e.g. `[::]` or `0.0.0.0`), they will be
    /// converted to localhost. This is a convenience for testing; in production you should prefer
    /// providing the correct addresses.
    pub async fn connect(&self, addrs: impl ToSocketAddrs) -> Result<ConnectedSession, Error> {
        ConnectedSession::new(self.clone(), normalise_addrs(addrs)?).await
    }

    /// Accept an incoming session.
    pub async fn accept(&self) -> Option<Result<AcceptedSession, Error>> {
        match self.server.lock().await.accept().await {
            Some(session) => Some(
                session
                    .ok()
                    .await
                    .map(|session| AcceptedSession {
                        peer_key: obtain_peer_key(&session),
                        session,
                    })
                    .map_err(|e| Error::Write(e.into())),
            ),
            None => None,
        }
    }

    /// Key used by this endpoint.
    pub fn key(&self) -> Arc<KeyPair> {
        self.key.key.clone()
    }

    /// Wait for all sessions on the endpoint to be cleanly shut down.
    ///
    /// Waiting for this condition before exiting ensures that a good-faith effort is made to notify
    /// peers of recent session closes, whereas exiting immediately could force them to wait out
    /// the idle timeout period.
    ///
    /// Does not proactively close existing sessions or cause incoming sessions to be
    /// rejected. Consider calling [`Endpoint::close()`] if that is desired.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await
    }

    /// Close all sessions immediately.
    ///
    /// Pending operations will fail immediately with `Connection(ConnectionError::LocallyClosed)`.
    /// No more data is sent to the peers beyond a `CONNECTION_CLOSE` frame, and the peers may drop
    /// buffered data upon receiving the `CONNECTION_CLOSE` frame.
    ///
    /// `code` and `reason` are not interpreted, and are provided directly to the peers.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to improve odds that it
    /// is preserved in full, it should be kept under 1KiB.
    ///
    /// See the notes on [`Session::close()`] for more information.
    pub fn close(&self, code: u32, reason: impl AsRef<[u8]>) {
        self.endpoint.close(
            // UNWRAP: VarInt is u64 internally, so the conversion is always valid
            web_transport_proto::error_to_http3(code)
                .try_into()
                .unwrap(),
            reason.as_ref(),
        );
    }
}

fn normalise_addrs(addrs: impl ToSocketAddrs) -> Result<Vec<SocketAddr>, Error> {
    let addrs: Vec<SocketAddr> = addrs
        .to_socket_addrs()?
        .map(|mut addr| {
            if addr.ip().is_unspecified() {
                addr.set_ip(match addr.ip() {
                    IpAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
                    IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
                });
            }

            addr
        })
        .collect();

    if addrs.is_empty() {
        return Err(Error::NoAddrs);
    }

    Ok(addrs)
}

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

    async fn new(endpoint: Endpoint, addrs: Vec<SocketAddr>) -> Result<Self, Error> {
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
    session: web_transport::Session,
    peer_key: Option<SubjectPublicKeyInfoDer<'static>>,
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

fn obtain_peer_key(conn: &quinn::Connection) -> Option<SubjectPublicKeyInfoDer<'static>> {
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

/// A Mushi error.
///
/// Mostly these are transport errors; at connection startup you may also encounter I/O and
/// addressing errors.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("session error: {0}")]
    Session(#[from] web_transport::SessionError),

    #[error("client error: {0}")]
    Client(#[from] web_transport::ClientError),

    #[error("connect error: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("connect error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("write error: {0}")]
    Write(web_transport::WriteError),

    #[error("read error: {0}")]
    Read(web_transport::ReadError),

    #[error("no addresses found")]
    NoAddrs,

    #[error("peer key mismatch on reconnection")]
    PeerKeyMismatch,
}

impl From<web_transport::WriteError> for Error {
    fn from(e: web_transport::WriteError) -> Self {
        match e {
            web_transport::WriteError::SessionError(e) => Error::Session(e),
            e => Error::Write(e),
        }
    }
}
impl From<web_transport::ReadError> for Error {
    fn from(e: web_transport::ReadError) -> Self {
        match e {
            web_transport::ReadError::SessionError(e) => Error::Session(e),
            e => Error::Read(e),
        }
    }
}
