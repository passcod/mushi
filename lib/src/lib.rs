//! Mushi is a [WebTransport] server that browsers authenticate by **certificate hash** instead of
//! web PKI.
//!
//! A browser can't talk to a device that has no publicly-trusted certificate: local addresses
//! can't get one, and mixed-content rules block plain HTTP. WebTransport's
//! [`serverCertificateHashes`] option is the sanctioned way out — the page supplies the SHA-256 of
//! the certificate it expects, and the browser skips chain validation entirely. Mushi is the
//! server side of that arrangement.
//!
//! The intended deployment is a **cloud app over real HTTPS plus a local device**: the page is
//! loaded from an origin the browser already trusts, that origin tells the page which certificate
//! hashes the device is currently serving, and the page connects straight to the device.
//!
//! Nothing needs to be installed in the browser — the native [`WebTransport`] API is enough.
//!
//! # What the browser imposes
//!
//! The certificate rules aren't Mushi's; they come from the WebTransport specification, and they
//! shape the whole design:
//!
//! - **ECDSA P-256 only.** RSA is banned outright, and Ed25519 is not permitted either.
//! - **Under 14 days of validity**, and the current time must fall inside it. Short life stands in
//!   for revocation, so certificates must be rotated rather than issued once.
//! - **SHA-256** is the only hash algorithm currently specified.
//! - **No client certificates.** The browser has no way to present one, at any layer. Authenticate
//!   peers over the session instead — see [`Request`] for what's available at handshake time.
//!
//! Because the browser pins a hash of the whole certificate, it doesn't care what's inside. That
//! makes the scheme naturally agile: [`serverCertificateHashes`] takes a *list*, so you can publish
//! hashes for several certificates at once and let the TLS handshake pick between them. Mushi
//! keeps [`SigScheme`] open for that reason, even though P-256 is the only scheme browsers accept
//! today.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), mushi::Error> {
//! let identity = mushi::Identity::generate()?;
//! let cert = identity.issue(mushi::DEFAULT_VALIDITY)?;
//!
//! // Hand this to the browser out of band, over an origin it already trusts.
//! println!("serverCertificateHashes: {}", cert.hash().to_hex());
//!
//! let server = mushi::Server::builder()
//!     .with_addr("[::]:4433".parse().unwrap())
//!     .with_certificate(cert)?;
//!
//! while let Some(request) = server.accept().await {
//!     // The path is the only part of the handshake the browser controls, so it carries both
//!     // the protocol selection and whatever token you authenticate with.
//!     match request.path() {
//!         "/echo" => {
//!             let session = request.ok().await?;
//!             let _ = session.recv_datagram().await?;
//!         }
//!         _ => request.reject(mushi::StatusCode::NOT_FOUND).await?,
//!     }
//! }
//! # Ok(())
//! # }
//! ```
#![warn(missing_docs)]

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use tokio::sync::Mutex;

pub use http::StatusCode;
pub use rcgen;
pub use time;
pub use url::Url;
pub use web_transport_quinn::{self as web_transport, quinn, quinn::rustls};

use base64::{
    Engine,
    engine::general_purpose::{
        STANDARD as BASE64, STANDARD_NO_PAD as BASE64_UNPADDED, URL_SAFE_NO_PAD as BASE64_URLSAFE,
    },
};
use bytes::{Buf, BufMut, Bytes};
use quinn::{congestion::ControllerFactory, crypto::rustls::QuicServerConfig};
use rcgen::{CertificateParams, DistinguishedName as Dn, DnType, KeyPair};
use rustls::{
    KeyLogFile, SignatureScheme,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use time::{Duration, OffsetDateTime};
use web_transport::{ALPN, crypto};

/// The longest a certificate may be valid for and still be accepted by a browser.
///
/// The WebTransport specification requires under two weeks. A certificate at exactly this length
/// is liable to be rejected by rounding, so [`Identity::issue`] refuses anything at or above it.
pub const MAX_VALIDITY: Duration = Duration::days(14);

/// A sensible certificate lifetime, leaving room to rotate before expiry.
pub const DEFAULT_VALIDITY: Duration = Duration::days(13);

/// A signature scheme for an [`Identity`].
///
/// This is the tuple of the [rustls] type (for TLS) and the corresponding [rcgen] type (for
/// issuing certificates).
///
/// Only [`SIGSCHEME_ECDSA256`] is accepted by browsers today. The type stays open because the
/// certificate-hash mechanism doesn't inspect the key, so widening this later needs no protocol
/// change — see [`BROWSER_SIGSCHEMES`].
pub type SigScheme = (SignatureScheme, &'static rcgen::SignatureAlgorithm);

/// Keys using ECDSA and the NIST P-256 curve.
///
/// The only scheme browsers currently accept for certificate-hash connections.
pub const SIGSCHEME_ECDSA256: SigScheme = (
    SignatureScheme::ECDSA_NISTP256_SHA256,
    &rcgen::PKCS_ECDSA_P256_SHA256,
);

/// Every scheme browsers currently accept for certificate-hash connections.
///
/// Checked by [`Identity::issue`]. Serving a certificate outside this set is legal — a native
/// client may well accept it — but no browser will connect.
pub const BROWSER_SIGSCHEMES: &[SigScheme] = &[SIGSCHEME_ECDSA256];

/// The long-lived key pair identifying a Mushi server.
///
/// The key outlives the certificates issued from it. Browsers pin the certificate rather than the
/// key, so rotating a certificate changes the hash even when the key stays the same; publish the
/// new hash before serving it.
#[derive(Debug, Clone)]
pub struct Identity {
    scheme: SigScheme,
    key: Arc<KeyPair>,
}

impl std::ops::Deref for Identity {
    type Target = KeyPair;
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl Identity {
    /// Generate a new random identity using ECDSA P-256.
    pub fn generate() -> Result<Self, Error> {
        Self::generate_for(SIGSCHEME_ECDSA256)
    }

    /// Generate a new random identity using a particular scheme.
    ///
    /// Prefer [`Identity::generate`] unless you're deliberately targeting non-browser clients:
    /// browsers reject everything outside [`BROWSER_SIGSCHEMES`].
    pub fn generate_for(scheme: SigScheme) -> Result<Self, Error> {
        Ok(Self {
            scheme,
            key: Arc::new(KeyPair::generate_for(scheme.1)?),
        })
    }

    /// Load an existing identity from a PEM-encoded PKCS#8 private key.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let key = KeyPair::from_pem(pem)?;
        let scheme = BROWSER_SIGSCHEMES
            .iter()
            .copied()
            .find(|(_, alg)| key.is_compatible(alg))
            .ok_or(Error::UnsupportedKey)?;
        Ok(Self {
            scheme,
            key: Arc::new(key),
        })
    }

    /// Load an existing identity from an [`rcgen::KeyPair`].
    ///
    /// Errors if the key pair isn't compatible with `scheme`.
    pub fn load(key: KeyPair, scheme: SigScheme) -> Result<Self, Error> {
        if !key.is_compatible(scheme.1) {
            return Err(Error::UnsupportedKey);
        }

        Ok(Self {
            scheme,
            key: Arc::new(key),
        })
    }

    /// The signature scheme this identity uses.
    pub fn scheme(&self) -> SigScheme {
        self.scheme
    }

    /// Issue a certificate for this identity.
    ///
    /// `validity` must be under [`MAX_VALIDITY`], or browsers will refuse the connection;
    /// [`DEFAULT_VALIDITY`] is a good choice.
    ///
    /// The certificate carries no subject alternative names. A matching hash replaces certificate
    /// validation wholesale, names included, so there is nothing for a SAN to assert: the device
    /// can be reached on any address without reissuing. A distinguished name is set because some
    /// stacks dislike a certificate with neither.
    ///
    /// The certificate is issued slightly in the past, so that a device whose clock is a little
    /// behind the browser's is still usable.
    pub fn issue(&self, validity: Duration) -> Result<Certificate, Error> {
        if validity >= MAX_VALIDITY {
            return Err(Error::ValidityTooLong(validity));
        }
        if validity <= Duration::ZERO {
            return Err(Error::ValidityTooShort(validity));
        }

        let mut params = CertificateParams::default();
        params.distinguished_name = Dn::new();
        params.distinguished_name.push(DnType::CommonName, "mushi");

        // Backdate slightly: certificate periods are checked by the browser at handshake, and a
        // device whose clock trails the browser's would otherwise be unreachable.
        let skew = Duration::minutes(5);
        let not_before = OffsetDateTime::now_utc() - skew;
        let not_after = not_before + validity;
        params.not_before = not_before;
        params.not_after = not_after;

        let cert = params.self_signed(&*self.key)?;
        let der = CertificateDer::from(cert.der().to_vec());
        let hash = CertHash::of(&der);

        Ok(Certificate {
            der,
            key: self.key.clone(),
            scheme: self.scheme,
            hash,
            not_before,
            not_after,
        })
    }
}

/// The hash of a certificate, as the browser expects it.
///
/// This mirrors the `WebTransportHash` dictionary: an algorithm name alongside the digest. Publish
/// both — a bare digest can't survive the algorithm changing.
///
/// The wire format is [Subresource Integrity][sri] syntax, `sha256-<standard base64>`. That's a
/// deliberate borrow: SRI's semantics are "any of these digests matching is acceptable", which is
/// exactly what `serverCertificateHashes` does with a list, and exactly what a rotation overlap
/// needs. A whole publishable set is therefore one space-separated string — see
/// [`CertHash::set_to_sri`] — with no schema to agree on or version.
///
/// Note that SRI and WebTransport spell the algorithm differently: `sha256` in the SRI token,
/// `sha-256` in the browser dictionary. [`CertHash::algorithm`] always holds the browser spelling,
/// so it can be handed to `WebTransportHash` directly.
///
/// [sri]: https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertHash {
    /// The hash algorithm, in the spelling the browser API uses (`sha-256`).
    pub algorithm: &'static str,

    /// The digest itself.
    pub value: Vec<u8>,
}

/// Algorithms recognised on the wire, as (SRI token, browser spelling).
///
/// Only `sha-256` is currently valid for WebTransport; the others are accepted when parsing so a
/// published set stays readable if that ever widens.
const HASH_ALGORITHMS: &[(&str, &str)] = &[
    ("sha256", "sha-256"),
    ("sha384", "sha-384"),
    ("sha512", "sha-512"),
];

impl CertHash {
    /// Compute the hash of a DER-encoded certificate.
    pub fn of(cert: &CertificateDer<'_>) -> Self {
        let provider = crypto::default_provider();
        Self {
            algorithm: "sha-256",
            value: crypto::sha256(&provider, cert).as_ref().to_vec(),
        }
    }

    /// The hash in [Subresource Integrity][sri] syntax, such as `sha256-47DEQpj8...`.
    ///
    /// This is also the [`Display`](std::fmt::Display) form.
    ///
    /// [sri]: https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
    pub fn to_sri(&self) -> String {
        let token = HASH_ALGORITHMS
            .iter()
            .find(|(_, browser)| *browser == self.algorithm)
            .map(|(sri, _)| *sri)
            // An algorithm outside the table can only come from constructing CertHash by hand;
            // fall back to stripping the hyphen rather than losing the value entirely.
            .map(str::to_owned)
            .unwrap_or_else(|| self.algorithm.replace('-', ""));

        format!("{token}-{}", BASE64.encode(&self.value))
    }

    /// Parse a single [Subresource Integrity][sri] token.
    ///
    /// Accepts standard or URL-safe base64, with or without padding, and ignores any `?options`
    /// suffix as SRI allows.
    ///
    /// [sri]: https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
    pub fn from_sri(sri: &str) -> Result<Self, Error> {
        let token = sri.trim();
        // SRI permits `hash-expression?options`; nothing here uses options, so drop them.
        let token = token.split('?').next().unwrap_or(token);

        // Standard base64 never contains '-', so the first one separates algorithm from digest.
        let (alg, digest) = token
            .split_once('-')
            .ok_or_else(|| Error::MalformedHash(sri.to_owned()))?;

        let algorithm = HASH_ALGORITHMS
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(alg))
            .map(|(_, browser)| *browser)
            .ok_or_else(|| Error::UnknownHashAlgorithm(alg.to_owned()))?;

        let value = BASE64
            .decode(digest)
            .or_else(|_| BASE64_UNPADDED.decode(digest))
            .or_else(|_| BASE64_URLSAFE.decode(digest))
            .map_err(|_| Error::MalformedHash(sri.to_owned()))?;

        Ok(Self { algorithm, value })
    }

    /// Format a whole set for publication: SRI tokens separated by spaces.
    ///
    /// This is what a browser needs during a rotation overlap — the served certificate plus any
    /// staged or recently-retired ones, so that a page holding any current snapshot can connect.
    pub fn set_to_sri(hashes: &[Self]) -> String {
        hashes
            .iter()
            .map(Self::to_sri)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Parse a published set of space-separated SRI tokens.
    ///
    /// Every token must parse; a set that is partly unreadable is more dangerous than one that
    /// fails loudly, since silently dropping a hash can make a device unreachable.
    pub fn set_from_sri(sri: &str) -> Result<Vec<Self>, Error> {
        sri.split_whitespace().map(Self::from_sri).collect()
    }

    /// The digest as lowercase hex.
    ///
    /// [`CertHash::to_sri`] is the preferred form; this is here for systems that already speak hex.
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(self.value.len() * 2);
        for byte in &self.value {
            use std::fmt::Write;
            // UNWRAP: writing to a String is infallible
            write!(out, "{byte:02x}").unwrap();
        }
        out
    }
}

impl std::str::FromStr for CertHash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_sri(s)
    }
}

impl std::fmt::Display for CertHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_sri())
    }
}

/// A certificate issued from an [`Identity`], along with the hash browsers pin it by.
#[derive(Debug, Clone)]
pub struct Certificate {
    der: CertificateDer<'static>,
    key: Arc<KeyPair>,
    scheme: SigScheme,
    hash: CertHash,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

impl Certificate {
    /// The hash to give the browser as `serverCertificateHashes`.
    pub fn hash(&self) -> &CertHash {
        &self.hash
    }

    /// The DER encoding of the certificate.
    pub fn der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    /// When the certificate becomes valid.
    pub fn not_before(&self) -> OffsetDateTime {
        self.not_before
    }

    /// When the certificate expires, after which browsers will refuse it.
    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }

    /// Whether the certificate is valid at the given time.
    pub fn is_valid_at(&self, when: OffsetDateTime) -> bool {
        when >= self.not_before && when < self.not_after
    }

    /// Whether the certificate could be accepted by a browser right now.
    ///
    /// False once it expires, or if it was issued under a scheme browsers don't accept.
    pub fn is_browser_valid(&self) -> bool {
        BROWSER_SIGSCHEMES.contains(&self.scheme) && self.is_valid_at(OffsetDateTime::now_utc())
    }

    fn certified_key(&self) -> Result<CertifiedKey, Error> {
        let provider = crypto::default_provider();
        Ok(CertifiedKey::from_der(
            vec![self.der.clone()],
            PrivateKeyDer::Pkcs8(self.key.serialize_der().into()),
            &provider,
        )?)
    }
}

/// Resolves the certificate to serve for an incoming handshake.
///
/// Held behind a lock so the certificate can be replaced without restarting the server, which is
/// what rotation will need.
#[derive(Debug)]
struct CertResolver {
    current: RwLock<(Arc<CertifiedKey>, Certificate)>,
}

impl CertResolver {
    fn certificate(&self) -> Certificate {
        // UNWRAP: the lock is only ever held for the length of a clone, and nothing panics under it
        self.current.read().unwrap().1.clone()
    }

    fn replace(&self, cert: Certificate) -> Result<(), Error> {
        let certified = Arc::new(cert.certified_key()?);
        // UNWRAP: as above
        *self.current.write().unwrap() = (certified, cert);
        Ok(())
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // UNWRAP: as above
        Some(self.current.read().unwrap().0.clone())
    }
}

/// Builds a [`Server`].
pub struct ServerBuilder {
    addr: SocketAddr,
    congestion_controller: Option<Arc<dyn ControllerFactory + Send + Sync + 'static>>,
}

impl std::fmt::Debug for ServerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBuilder")
            .field("addr", &self.addr)
            .field(
                "congestion_controller",
                &self.congestion_controller.as_ref().map(|_| "<factory>"),
            )
            .finish()
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBuilder {
    /// Start building a server bound to `[::]:0`.
    pub fn new() -> Self {
        Self {
            addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            congestion_controller: None,
        }
    }

    /// Bind to the given address.
    ///
    /// `[::]:0` binds every interface on a random port; use [`Server::local_addr`] to find out
    /// which.
    pub fn with_addr(mut self, addr: SocketAddr) -> Self {
        self.addr = addr;
        self
    }

    /// Use a particular congestion control strategy.
    ///
    /// Pick from [`quinn::congestion`] to trade throughput against latency. Defaults to Cubic
    /// (RFC 8312).
    pub fn with_congestion_control(
        mut self,
        cc: Arc<dyn ControllerFactory + Send + Sync + 'static>,
    ) -> Self {
        self.congestion_controller = Some(cc);
        self
    }

    /// Bind the socket and start serving `cert`.
    pub fn with_certificate(self, cert: Certificate) -> Result<Server, Error> {
        let provider = crypto::default_provider();
        let resolver = Arc::new(CertResolver {
            current: RwLock::new((Arc::new(cert.certified_key()?), cert)),
        });

        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        tls.alpn_protocols = vec![ALPN.as_bytes().to_vec()];

        if cfg!(debug_assertions) {
            tls.key_log = Arc::new(KeyLogFile::new());
        }

        let mut transport = quinn::TransportConfig::default();
        if let Some(cc) = self.congestion_controller {
            transport.congestion_controller_factory(cc);
        }

        let mut config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
        config.transport_config(Arc::new(transport));

        let endpoint = quinn::Endpoint::server(config, self.addr)?;

        Ok(Server {
            inner: Arc::new(Mutex::new(web_transport::Server::new(endpoint.clone()))),
            endpoint,
            resolver,
        })
    }
}

/// A Mushi server, accepting WebTransport sessions from browsers.
///
/// Can be cloned to get multiple handles to the same socket. Accepting is serialised across
/// clones, so only one call to [`Server::accept`] makes progress at a time.
#[derive(Clone)]
pub struct Server {
    inner: Arc<Mutex<web_transport::Server>>,
    endpoint: quinn::Endpoint,
    resolver: Arc<CertResolver>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("endpoint", &self.endpoint)
            .field("cert", &self.resolver.certificate())
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Start building a server.
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// Accept an incoming session request.
    ///
    /// Returns `None` once the server is closed. The request is not yet a session: inspect it and
    /// then call [`Request::ok`] or [`Request::reject`].
    pub async fn accept(&self) -> Option<Request> {
        self.inner
            .lock()
            .await
            .accept()
            .await
            .map(|inner| Request { inner })
    }

    /// The certificate currently being served.
    pub fn certificate(&self) -> Certificate {
        self.resolver.certificate()
    }

    /// Replace the certificate served to new connections.
    ///
    /// Existing sessions are untouched. Publish the new hash *before* calling this, and keep
    /// publishing the old one until every browser has had a chance to pick up the change —
    /// `serverCertificateHashes` accepts a list precisely so the overlap is seamless.
    pub fn set_certificate(&self, cert: Certificate) -> Result<(), Error> {
        self.resolver.replace(cert)
    }

    /// The local address the underlying socket is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.endpoint.local_addr().map_err(Error::from)
    }

    /// The number of connections (≈sessions) currently open.
    pub fn open_connections(&self) -> usize {
        self.endpoint.open_connections()
    }

    /// QUIC activity stats.
    pub fn stats(&self) -> quinn::EndpointStats {
        self.endpoint.stats()
    }

    /// Wait for all sessions to be cleanly shut down.
    ///
    /// Waiting before exiting makes a good-faith effort to notify peers, where exiting immediately
    /// would force them to wait out the idle timeout. Does not close anything itself; see
    /// [`Server::close`].
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await
    }

    /// Close all sessions immediately.
    ///
    /// Pending operations fail at once, and nothing is sent beyond a `CONNECTION_CLOSE` frame, so
    /// peers may drop data they had buffered. See [`Session::close`].
    pub fn close(&self, code: u32, reason: impl AsRef<[u8]>) {
        self.endpoint.close(
            // UNWRAP: VarInt is a u64 internally, so this conversion always succeeds
            web_transport_proto::error_to_http3(code)
                .try_into()
                .unwrap(),
            reason.as_ref(),
        );
    }
}

/// An incoming session, awaiting a decision.
///
/// This is where you route and authorise. The browser controls very little of the handshake: it
/// cannot set request headers, and WebTransport does not send cookies. In practice the **URL path
/// is the only channel it has**, so it carries both the protocol selection and any token you
/// authenticate with. The [`Origin`](Request::origin) header is set by the browser itself and is
/// worth checking too.
pub struct Request {
    inner: web_transport::Request,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("url", self.url())
            .field("protocols", &self.protocols())
            .field("remote_address", &self.remote_address())
            .finish_non_exhaustive()
    }
}

impl Request {
    /// The full URL the browser connected to.
    pub fn url(&self) -> &Url {
        &self.inner.url
    }

    /// The path component of the URL.
    pub fn path(&self) -> &str {
        self.inner.url.path()
    }

    /// The `Origin` header, as set by the browser.
    ///
    /// Absent for non-browser clients, which can claim any origin they like — this identifies the
    /// page, and is not on its own an authentication.
    pub fn origin(&self) -> Option<&str> {
        self.inner
            .headers
            .get(http::header::ORIGIN)
            .and_then(|v| v.to_str().ok())
    }

    /// The subprotocols the client offered, in preference order.
    ///
    /// Not supported by every browser — Firefox doesn't implement subprotocol negotiation — so
    /// treat this as a hint and select on [`Request::path`] instead.
    pub fn protocols(&self) -> &[String] {
        &self.inner.protocols
    }

    /// The raw HTTP/3 headers of the CONNECT request.
    pub fn headers(&self) -> &http::HeaderMap {
        &self.inner.headers
    }

    /// The address the client is connecting from.
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.conn().remote_address()
    }

    /// Accept the session.
    pub async fn ok(self) -> Result<Session, Error> {
        Ok(Session {
            inner: self.inner.ok().await?,
        })
    }

    /// Accept the session, selecting one of the offered subprotocols.
    ///
    /// The protocol must be one the client offered. Clients that don't support negotiation ignore
    /// this.
    pub async fn ok_with_protocol(self, protocol: &str) -> Result<Session, Error> {
        let response = web_transport_proto::ConnectResponse::OK.with_protocol(protocol);
        Ok(Session {
            inner: self.inner.respond(response).await?,
        })
    }

    /// Reject the session with an HTTP status code.
    pub async fn reject(self, status: StatusCode) -> Result<(), Error> {
        self.inner.reject(status).await?;
        Ok(())
    }
}

/// An established session, able to open streams and send datagrams.
///
/// Can be cloned to get multiple handles to the same connection. Once every handle is dropped the
/// session closes with code 0; close it explicitly with [`Session::close`] to say more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    inner: web_transport::Session,
}

impl Session {
    /// The subprotocol negotiated for this session, if any.
    pub fn protocol(&self) -> Option<&str> {
        self.inner.protocol()
    }

    /// Access the underlying QUIC connection.
    ///
    /// # Safety
    ///
    /// You must not call anything that alters session state or sends packets; that would corrupt
    /// the WebTransport layer above. Reading statistics (`remote_address()`, `stats()`,
    /// `close_reason()`, and so on) is safe.
    pub unsafe fn as_quic(&self) -> &quinn::Connection {
        &self.inner
    }

    /// Wait for the peer to open a unidirectional stream.
    pub async fn accept_uni(&self) -> Result<RecvStream, Error> {
        Ok(RecvStream::new(self.inner.accept_uni().await?))
    }

    /// Wait for the peer to open a bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), Error> {
        let (s, r) = self.inner.accept_bi().await?;
        Ok((SendStream::new(s), RecvStream::new(r)))
    }

    /// Open a bidirectional stream.
    ///
    /// May wait when there are too many concurrent streams.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), Error> {
        let (s, r) = self.inner.open_bi().await?;
        Ok((SendStream::new(s), RecvStream::new(r)))
    }

    /// Open a unidirectional stream.
    ///
    /// May wait when there are too many concurrent streams. Note that WebTransport is symmetric
    /// once established: the server can push to the browser without being asked.
    pub async fn open_uni(&self) -> Result<SendStream, Error> {
        Ok(SendStream::new(self.inner.open_uni().await?))
    }

    /// Send an unreliable datagram.
    ///
    /// Datagrams may be dropped for any reason, including congestion, packet loss, exceeding
    /// [`Session::max_datagram_size`], or the peer not reading them.
    pub fn send_datagram(&self, payload: Bytes) -> Result<(), Error> {
        Ok(self.inner.send_datagram(payload)?)
    }

    /// The largest datagram that can be sent.
    pub fn max_datagram_size(&self) -> usize {
        self.inner.max_datagram_size()
    }

    /// Receive a datagram.
    pub async fn recv_datagram(&self) -> Result<Bytes, Error> {
        Ok(self.inner.read_datagram().await?)
    }

    /// Close the session immediately.
    ///
    /// Pending operations fail at once. Nothing is sent beyond a `CONNECTION_CLOSE` frame, and the
    /// peer may drop stream data it hasn't yet handed to its application — including data it
    /// already acknowledged. `reason` is truncated to fit a single packet, so keep it under 1KiB.
    ///
    /// Only the peer that received data last can know it all arrived. To close gracefully, have
    /// that side call this, and give the frame time to arrive with [`Server::wait_idle`];
    /// otherwise the peer times the session out after 30 seconds.
    pub fn close(&self, code: u32, reason: impl AsRef<[u8]>) {
        self.inner.close(code, reason.as_ref())
    }

    /// Wait until the session is closed, and report why.
    pub async fn closed(&self) -> Error {
        Error::Session(self.inner.closed().await)
    }
}

/// An outgoing stream of bytes.
///
/// Flow controlled by the peer's receive window. Closed with a graceful FIN when dropped.
#[derive(Debug)]
pub struct SendStream {
    inner: web_transport::SendStream,
}

impl SendStream {
    fn new(inner: web_transport::SendStream) -> Self {
        Self { inner }
    }

    /// Write the whole buffer to the stream.
    pub async fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.inner.write_all(buf).await?;
        Ok(())
    }

    /// Write a buffer to the stream, advancing its internal position.
    ///
    /// May be polled to perform partial writes.
    pub async fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Result<(), Error> {
        while buf.has_remaining() {
            let size = self.inner.write(buf.chunk()).await?;
            buf.advance(size);
        }

        Ok(())
    }

    /// Finish the stream cleanly, signalling there's nothing more to send.
    pub fn finish(&mut self) -> Result<(), Error> {
        self.inner.finish()?;
        Ok(())
    }

    /// Set the stream's priority.
    ///
    /// Lower values are sent first, though they aren't guaranteed to arrive first.
    pub fn set_priority(&mut self, order: i32) {
        self.inner.set_priority(order).ok();
    }

    /// Reset the stream immediately, closing it with an error code.
    pub fn reset(&mut self, code: u32) {
        self.inner.reset(code).ok();
    }
}

/// An incoming stream of bytes.
///
/// Bytes arrive in order and are flow controlled. Closed with `STOP_SENDING` code 0 when dropped.
#[derive(Debug)]
pub struct RecvStream {
    inner: web_transport::RecvStream,
}

impl RecvStream {
    fn new(inner: web_transport::RecvStream) -> Self {
        Self { inner }
    }

    /// Read the next chunk of data, up to `max` bytes.
    ///
    /// Returns a chunk rather than copying, which may be more efficient. `None` means the stream
    /// has finished.
    pub async fn read(&mut self, max: usize) -> Result<Option<Bytes>, Error> {
        Ok(self
            .inner
            .read_chunk(max, true)
            .await?
            .map(|chunk| chunk.bytes))
    }

    /// Read into the provided buffer, advancing it by the number of bytes read.
    ///
    /// Returns the number of bytes read, or `None` if the stream has finished.
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

    /// Send a `STOP_SENDING` code, asking the peer to stop writing.
    pub fn stop(&mut self, code: u32) {
        self.inner.stop(code).ok();
    }
}

/// A Mushi error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("session error: {0}")]
    Session(#[from] web_transport::SessionError),

    #[error("server error: {0}")]
    Server(#[from] web_transport::ServerError),

    #[error("write error: {0}")]
    Write(web_transport::WriteError),

    #[error("read error: {0}")]
    Read(web_transport::ReadError),

    #[error("certificate error: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("tls suite error: {0}")]
    NoInitialCipherSuite(#[from] quinn::crypto::rustls::NoInitialCipherSuite),

    #[error("key is not usable with any supported signature scheme")]
    UnsupportedKey,

    #[error("malformed certificate hash: {0:?}")]
    MalformedHash(String),

    #[error("unknown hash algorithm: {0:?}")]
    UnknownHashAlgorithm(String),

    #[error("validity of {0} is too long: browsers require under {MAX_VALIDITY}")]
    ValidityTooLong(Duration),

    #[error("validity of {0} is not positive")]
    ValidityTooShort(Duration),
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

impl From<web_transport::ClosedStream> for Error {
    fn from(_: web_transport::ClosedStream) -> Self {
        Error::Write(web_transport::WriteError::ClosedStream)
    }
}
