use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use crate::key::*;
use crate::{AcceptedSession, ConnectedSession, error::Error};
use rustls::{CertificateError, pki_types::SubjectPublicKeyInfoDer};
use web_transport_quinn::{self as web_transport, quinn, quinn::rustls};

use quinn::{
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
use web_transport::ALPN;

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
    pub(crate) options: Arc<EndpointOptions>,
    pub(crate) client_config: quinn::ClientConfig,
    pub(crate) server: Arc<Mutex<web_transport::Server>>,
    pub(crate) key: Arc<Key>,
    pub(crate) endpoint: quinn::Endpoint,
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
    // TODO: multiple server binds
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
                        peer_key: crate::obtain_peer_key(&session),
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

    /// Wait for all links on the endpoint to be cleanly shut down.
    ///
    /// Waiting for this condition before exiting ensures that a good-faith effort is made to
    /// notify peers of recent link closures, whereas exiting immediately could force them to wait
    /// out the idle timeout period.
    ///
    /// Does not proactively close existing links or cause incoming links to be rejected. Consider
    /// calling [`Endpoint::close()`] if that is desired.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await
    }

    /// Close all links immediately.
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
    /// See the notes on [`Link::close()`] for more information.
    pub fn close(&self, code: u64, reason: impl AsRef<[u8]>) {
        self.endpoint.close(
            // UNWRAP: VarInt is u64 internally, so the conversion is always valid
            code.try_into().unwrap(),
            reason.as_ref(),
        );
    }
}

pub(crate) fn normalise_addrs(addrs: impl ToSocketAddrs) -> Result<Vec<SocketAddr>, Error> {
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
