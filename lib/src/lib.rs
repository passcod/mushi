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
//! just-in-time short-lived certificate (valid for 2 minutes).
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
//! decide whether authorisation beyond peer public key trust is required, and how.
//!
//! # Example
//!
//! ```ignore
//! #[tokio::main]
//! async fn main() {
//!     mushi::install_crypto_provider();
//!
//!     let key = mushi::EndpointKey::generate().unwrap();
//!     let policy = Arc::new(mushi::AllowAllConnections);
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
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};

pub use rcgen;
pub use rustls::{
    CertificateError,
    pki_types::{SubjectPublicKeyInfoDer, UnixTime},
};
pub use url::Url;
pub use web_transport_quinn::{self as web_transport, quinn, quinn::rustls};

use bytes::{Buf, BufMut, Bytes};
use quinn::{
    ApplicationClose, ConnectionError,
    congestion::ControllerFactory,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rcgen::{CertificateParams, DistinguishedName as Dn, DnType, KeyPair};
use rustls::{
    DigitallySignedStruct, DistinguishedName, KeyLogFile, SignatureScheme,
    client::{
        ResolvesClientCert,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, alg_id},
    server::{
        ClientHello, ParsedCertificate, ResolvesServerCert,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use tracing::trace;
use web_transport::{ALPN, SessionError};

/// Install a default [`CryptoProvider`] specialised for Mushi applications.
///
/// This uses _ring_ and specifically disallows all uses of RSA. If you require RSA for other TLS
/// or _ring_ applications, either use the `with_provider` variants of builders for these, or use
/// [`rustls::crypto::ring::default_provider()`] directly instead.
pub fn install_crypto_provider() {
    let mut provider = rustls::crypto::ring::default_provider();
    let algos = Box::leak(
        provider
            .signature_verification_algorithms
            .all
            .iter()
            .cloned()
            .filter(|a| a.public_key_alg_id() != alg_id::RSA_ENCRYPTION)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    let mappings = Box::leak(
        provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .cloned()
            .filter(|(sig, _)| sig.as_str().is_some_and(|s| !s.contains("RSA")))
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    provider.signature_verification_algorithms = WebPkiSupportedAlgorithms {
        all: algos,
        mapping: mappings,
    };
    trace!(?provider, "mushi crypto provider");
    provider.install_default().unwrap();
}

/// A key pair that identifies and authenticates an [`Endpoint`].
#[derive(Debug, Clone)]
pub struct EndpointKey {
    scheme: SigScheme,
    key: Arc<KeyPair>,

    /// How long certificates should be valid for. Defaults to 2 minutes.
    pub validity: Duration,
}

impl std::ops::Deref for EndpointKey {
    type Target = KeyPair;
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

/// A signature scheme for generating and using an [`EndpointKey`].
///
/// Different endpoints can have different sigschemes and interoperate.
///
/// A SigScheme is the tuple of the [rustls] type (for TLS) and the corresponding [rcgen] type (for
/// generating certificates). The `SIGSCHEME_*` constants provide for common schemes but it is
/// possible to make your own should the libraries support more.
pub type SigScheme = (SignatureScheme, &'static rcgen::SignatureAlgorithm);

/// Small keys using the [Ed25519](https://ed25519.cr.yp.to/) scheme.
pub const SIGSCHEME_ED25519: SigScheme = (SignatureScheme::ED25519, &rcgen::PKCS_ED25519);

/// Keys using the [ECDSA] scheme and the NIST P-256 curve.
///
/// [ECDSA]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
pub const SIGSCHEME_ECDSA256: SigScheme = (
    SignatureScheme::ECDSA_NISTP256_SHA256,
    &rcgen::PKCS_ECDSA_P256_SHA256,
);

/// Keys using the [ECDSA] scheme and the NIST P-384 curve.
///
/// [ECDSA]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
pub const SIGSCHEME_ECDSA384: SigScheme = (
    SignatureScheme::ECDSA_NISTP384_SHA384,
    &rcgen::PKCS_ECDSA_P384_SHA384,
);

const MUSHI_TLD: &str = "xn--zqsr9q"; // 慕士

impl EndpointKey {
    /// Generate a new random key using the default scheme.
    pub fn generate() -> Result<Self, rcgen::Error> {
        Self::generate_for(SIGSCHEME_ED25519)
    }

    /// Generate a new random key using a particular scheme.
    pub fn generate_for(scheme: SigScheme) -> Result<Self, rcgen::Error> {
        Ok(Self {
            scheme,
            key: Arc::new(KeyPair::generate_for(scheme.1)?),
            validity: Duration::MINUTE * 2,
        })
    }

    /// Load an existing key from a [`rcgen::KeyPair`].
    ///
    /// Panics if `scheme` doesn't match the keypair.
    pub fn load(key: KeyPair, scheme: SigScheme) -> Self {
        if !key.compatible_algs().any(|alg| alg == scheme.1) {
            panic!("KeyPair is not compatible with {scheme:?}");
        }

        Self {
            scheme,
            key: Arc::new(key),
            validity: Duration::MINUTE * 2,
        }
    }

    fn supports_sigschemes(&self, requested: &[SignatureScheme]) -> bool {
        requested.contains(&self.scheme.0)
    }

    fn get_certificate(&self) -> Option<Arc<CertifiedKey>> {
        let cert = self.make_certificate().ok()?;
        let provider = CryptoProvider::get_default().expect("a default CryptoProvider must be set");
        Some(Arc::new(
            CertifiedKey::from_der(
                vec![cert.der().to_owned()],
                PrivateKeyDer::Pkcs8(self.key.serialize_der().into()),
                &provider,
            )
            .ok()?,
        ))
    }

    /// Generate a certificate for this key.
    ///
    /// This is primarily used internally, but exposed for convenience if you're implementing the
    /// transport yourself and don't want to bother making certificates correctly.
    pub fn make_certificate(&self) -> Result<rcgen::Certificate, rcgen::Error> {
        // some stacks balk if certificates don't have a SAN or DN.
        // generate a fake SAN based on the fingerprint of the public key
        // this plus the xn-- prefix = a 62-character DNS label, right under the limit
        let print = ring::digest::digest(&ring::digest::SHA256, &self.key.public_key_der());
        let puny = idna::punycode::encode_str(&base65536::encode(&print, None))
            .unwrap_or(MUSHI_TLD.to_string());

        // append a non-existing TLD so we never conflict with Internet resources
        let san = format!("xn--{puny}.{MUSHI_TLD}");

        let mut cert = CertificateParams::new(vec![san.clone()])?;
        cert.distinguished_name = Dn::new();
        cert.distinguished_name.push(DnType::CommonName, san);

        // issue certificates valid slightly in the past, so that servers that aren't
        // synchronised in time properly can talk to each other. certificate periods
        // are checked on handshake only, and Mushi generates certificates just-in-time
        let start = OffsetDateTime::now_utc() - Duration::MINUTE;
        cert.not_before = start;
        cert.not_after = start + Duration::MINUTE + self.validity;

        cert.self_signed(&self.key)
    }
}

impl ResolvesClientCert for EndpointKey {
    fn resolve(&self, _hints: &[&[u8]], schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        if self.supports_sigschemes(schemes) {
            self.get_certificate()
        } else {
            None
        }
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl ResolvesServerCert for EndpointKey {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.get_certificate()
    }
}

/// The "allower" trait, which defines a peer trust policy.
pub trait AllowConnection: std::fmt::Debug + Send + Sync + 'static {
    /// Given a public key, determine whether a connection (peer) should be allowed.
    ///
    /// Return `Ok(())` to allow the peer to connect (or be connected to), and `Err(_)` to reject
    /// the peer. You should select an appropriate [`CertificateError`]; if in doubt, use
    /// [`ApplicationVerificationFailure`](CertificateError::ApplicationVerificationFailure).
    ///
    /// `now` provides a normalised timestamp from within the TLS machinery, which can be used for
    /// consistent calculations if time is a relevant decision factor.
    fn allow_public_key(
        &self,
        key: SubjectPublicKeyInfoDer<'_>,
        now: UnixTime,
    ) -> Result<(), CertificateError>;

    /// Whether incoming peers need to provide a certificate.
    ///
    /// This is `true` by default, and is the expectation in Mushi applications. In certain
    /// use-cases, allowing "anonymous" clients may be necessary; take care to implement your own
    /// authorisation layer as required.
    fn require_client_auth(&self) -> bool {
        true
    }
}

/// A convenience allower which accepts all public keys.
///
/// This is not recommended for use in real applications, but may be useful for testing.
#[derive(Debug, Clone, Copy)]
pub struct AllowAllConnections;

impl AllowConnection for AllowAllConnections {
    fn allow_public_key(
        &self,
        _key: SubjectPublicKeyInfoDer<'_>,
        _now: UnixTime,
    ) -> Result<(), CertificateError> {
        Ok(())
    }
}

/// Internal implementation detail to avoid orphan-impl errors.
#[derive(Debug, Clone)]
struct ConnectionAllower(Arc<dyn AllowConnection>);

impl ServerCertVerifier for ConnectionAllower {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        self.0
            .allow_public_key(cert.subject_public_key_info(), now)
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

impl ClientCertVerifier for ConnectionAllower {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        self.0
            .allow_public_key(cert.subject_public_key_info(), now)
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
        self.0.require_client_auth()
    }
}

/// The main entrypoint to create connections to, and accept connections from other Mushi peers.
///
/// Generally, an application will have a single endpoint instance. This results in more optimal
/// network behaviour, and as a single endpoint can have sessions to any number of peers, and each
/// session supports many concurrent datagrams and streams, there's little need (outside of
/// testing) for multiple endpoints.
///
/// Before creating an endpoint, ensure that a default [`rustls::crypto::CryptoProvider`] has been
/// installed, preferably using [`install_crypto_provider()`].
#[derive(Clone)]
pub struct Endpoint {
    client_config: quinn::ClientConfig,
    server: Arc<Mutex<web_transport::Server>>,
    key: Arc<EndpointKey>,
    endpoint: quinn::Endpoint,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let server = &f
            .debug_struct("web_transport_quinn::Server")
            .finish_non_exhaustive()?;
        f.debug_struct("Endpoint")
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
    /// `allower` is the trust policy for remote peers: incoming (client certificate) and outgoing
    /// (server certificate) peers will have their public key extracted and checked by the
    /// [`AllowConnection`] implementation.
    ///
    /// `cc` is the congestion control strategy for the QUIC state machine. You can select
    /// different strategies from [`quinn::congestion`] or elsewhere to optimise for throughput or
    /// latency, or you can use `None` to select the default strategy (Cubic, aka RFC 8312).
    pub fn new(
        bind_to: impl ToSocketAddrs,
        key: EndpointKey,
        allower: Arc<dyn AllowConnection>,
        cc: Option<Arc<(dyn ControllerFactory + Send + Sync + 'static)>>,
    ) -> Result<Self, Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = Arc::new(key);
        let allower = Arc::new(ConnectionAllower(allower));

        let mut server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(allower.clone())
            .with_cert_resolver(key.clone());
        server_config.alpn_protocols = vec![ALPN.to_vec()];

        let mut client_config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(allower)
            .with_client_cert_resolver(key.clone());
        client_config.alpn_protocols = vec![ALPN.to_vec()];

        if cfg!(debug_assertions) {
            server_config.key_log = Arc::new(KeyLogFile::new());
            client_config.key_log = server_config.key_log.clone();
        }

        let mut transport = quinn::TransportConfig::default();
        if let Some(cc) = cc {
            transport.congestion_controller_factory(cc.clone());
        }
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
                Ok(s) => { endpoint = Some(s); break; },
                Err(err) => { last_err = Some(err); }
            }
        }
        let mut endpoint = match (endpoint, last_err) {
            (Some(e), _) => e,
            (None, Some(err)) => return Err(err.into()),
            (None, None) => return Err(Error::NoAddrs),
        };
        endpoint.set_default_client_config(client_config.clone());

        Ok(Self {
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
    pub async fn connect(&self, addrs: impl ToSocketAddrs) -> Result<Session, Error> {
        let mut last_err = None;
        for mut addr in addrs.to_socket_addrs()? {
            if addr.ip().is_unspecified() {
                addr.set_ip(match addr.ip() {
                    IpAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
                    IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
                });
            }
            let url = Url::parse(&format!("https://{addr}")).unwrap();
            let conn =
                self.endpoint
                    .connect_with(self.client_config.clone(), addr, "mushi.mushi")?;
            let conn = conn.await?;

            match web_transport::Session::connect(conn, &url).await {
                Ok(s) => return Ok(Session::new(s)),
                Err(e) => last_err = Some(Error::from(e)),
            }
        }

        Err(last_err.unwrap_or(Error::NoAddrs))
    }

    /// Accept an incoming session.
    pub async fn accept(&self) -> Option<Result<Session, Error>> {
        match self.server.lock().await.accept().await {
            Some(session) => Some(
                session
                    .ok()
                    .await
                    .map(Session::new)
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
    /// rejected. Consider calling [`Session::close()`] if that is desired.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await
    }
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    inner: web_transport::Session,
    peer_key: Option<SubjectPublicKeyInfoDer<'static>>,
}

impl Session {
    fn new(session: web_transport::Session) -> Self {
        let peer_key = session.peer_identity().and_then(|id| {
            let certs: Vec<CertificateDer> = *id.downcast().ok()?;
            for cert in certs {
                let Ok(cert) = ParsedCertificate::try_from(&cert) else {
                    continue;
                };
                return Some(cert.subject_public_key_info());
            }

            None
        });

        Self {
            inner: session,
            peer_key,
        }
    }

    /// The public key of the remote peer.
    ///
    /// This may be unavailable if `require_client_auth` returned `false` in the Endpoint's
    /// [`AllowConnection`] instance.
    pub fn peer_key(&self) -> Option<&SubjectPublicKeyInfoDer<'_>> {
        self.peer_key.as_ref()
    }

    /// Get access to the underlying QUIC Connection.
    ///
    /// Safety: you must not use any methods that alter the session state, nor any that send
    /// packets. This may corrupt the WebTransport state layered on top.
    ///
    /// Accessing statistical and factual information (such as `peer_identity()`,
    /// `remote_address()`, `stats()`, `close_reason()`, etc) is safe.
    pub unsafe fn as_quic(&self) -> &quinn::Connection {
        &self.inner
    }

    /// Wait until the peer creates a new unidirectional stream.
    ///
    /// Will error if the connection is closed.
    pub async fn accept_uni(&self) -> Result<RecvStream, Error> {
        let inner = self.inner.clone();
        let stream = inner.accept_uni().await?;
        Ok(RecvStream::new(stream))
    }

    /// Wait until the peer creates a new bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), Error> {
        let (s, r) = self.inner.accept_bi().await?;
        Ok((SendStream::new(s), RecvStream::new(r)))
    }

    /// Open a new bidirectional stream.
    ///
    /// May wait when there are too many concurrent streams.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), Error> {
        let inner = self.inner.clone();
        Ok(inner
            .open_bi()
            .await
            .map(|(s, r)| (SendStream::new(s), RecvStream::new(r)))?)
    }

    /// Open a new unidirectional stream.
    ///
    /// May wait when there are too many concurrent streams.
    pub async fn open_uni(&self) -> Result<SendStream, Error> {
        let inner = self.inner.clone();
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
    pub fn send_datagram(&self, payload: Bytes) -> Result<(), Error> {
        let inner = self.inner.clone();
        Ok(inner.send_datagram(payload)?)
    }

    /// The maximum size of a datagram that can be sent.
    pub async fn max_datagram_size(&self) -> usize {
        self.inner.max_datagram_size()
    }

    /// Receive a datagram over the network.
    pub async fn recv_datagram(&self) -> Result<Bytes, Error> {
        let inner = self.inner.clone();
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
    pub fn close(&self, code: u32, reason: &str) {
        let inner = self.inner.clone();
        inner.close(code, reason.as_bytes())
    }

    /// Wait until the connection is closed.
    ///
    /// Returns `Ok(None)` if the connection was closed locally, `Ok(Some(_))` if the connection
    /// was closed by a peer (e.g. with `close()`), and `Err(_)` for other unexpected reasons.
    pub async fn closed(&self) -> Result<Option<ApplicationClose>, Error> {
        match self.inner.closed().await {
            SessionError::ConnectionError(ConnectionError::LocallyClosed) => Ok(None),
            SessionError::ConnectionError(ConnectionError::ApplicationClosed(ac)) => Ok(Some(ac)),
            e => Err(Error::Session(e)),
        }
    }
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
