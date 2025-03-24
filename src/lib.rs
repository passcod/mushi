use std::{net::ToSocketAddrs, sync::Arc};

pub use web_transport_quinn::{self as web_transport, quinn, quinn::rustls};

use bytes::{Buf, BufMut, Bytes};
use quinn::{congestion::ControllerFactory, crypto::rustls::QuicClientConfig};
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::{
        ResolvesClientCert,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
    server::{
        ClientHello, ResolvesServerCert,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::{CertifiedKey, SigningKey},
};
use url::Url;
use web_transport::ALPN;

#[derive(Debug, Clone)]
struct EndpointKey {
    key: Arc<dyn SigningKey>,
}

impl EndpointKey {
    fn preferred_sigscheme(&self) -> SignatureScheme {
        todo!()
    }

    fn supports_sigschemes(&self, _requested: &[SignatureScheme]) -> Option<SignatureScheme> {
        todo!("figure out best supported scheme from requested")
    }

    fn make_certificate(&self, _scheme: SignatureScheme) -> Arc<CertifiedKey> {
        todo!()
    }
}

impl ResolvesClientCert for EndpointKey {
    fn resolve(&self, _hints: &[&[u8]], schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        if let Some(scheme) = self.supports_sigschemes(schemes) {
            Some(self.make_certificate(scheme))
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
        Some(self.make_certificate(self.preferred_sigscheme()))
    }
}

pub trait AllowConnection: std::fmt::Debug + Send + Sync + 'static {
    fn allow_public_key(
        &self,
        key: SubjectPublicKeyInfoDer<'_>,
        now: UnixTime,
    ) -> Result<(), rustls::CertificateError>;
}

#[derive(Debug, Clone)]
pub struct ConnectionAllower(pub Arc<dyn AllowConnection>);

impl ServerCertVerifier for ConnectionAllower {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let key = todo!("parse certificate and get a pki");
        self.0
            .allow_public_key(key, now)
            .map_err(rustls::Error::from)
            .and(Ok(ServerCertVerified::assertion()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        unimplemented!("mushi works exclusively over TLS1.3")
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        todo!()
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        todo!()
    }
}

impl ClientCertVerifier for ConnectionAllower {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let key = todo!("parse certificate and get a pki");
        self.0
            .allow_public_key(key, now)
            .map_err(rustls::Error::from)
            .and(Ok(ClientCertVerified::assertion()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        unimplemented!("mushi works exclusively over TLS1.3")
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        todo!()
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        todo!()
    }
}

/// Used to dial outgoing [Session]s or receive incoming [Session]s.
pub struct Endpoint {
    client: web_transport::Client,
    server: web_transport::Server,
    key: Arc<EndpointKey>,
}
// TODO: impl Debug

impl Endpoint {
    pub fn new(
        bind_to: impl ToSocketAddrs,
        key: Arc<dyn SigningKey>,
        allower: Arc<dyn AllowConnection>,
        cc: Option<Arc<(dyn ControllerFactory + Send + Sync + 'static)>>,
    ) -> Result<Self, Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = Arc::new(EndpointKey { key });
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

        let mut client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_config).unwrap()));
        let mut transport = quinn::TransportConfig::default();
        if let Some(cc) = cc {
            transport.congestion_controller_factory(cc.clone());
        }
        client_config.transport_config(transport.into());

        let mut endpoint =
            quinn::Endpoint::client(bind_to.to_socket_addrs().unwrap().next().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config.clone());

        Ok(Self {
            key,
            client: web_transport::Client::new(endpoint.clone(), client_config),
            server: web_transport::Server::new(endpoint),
        })
    }

    /// Connect to a server.
    pub async fn connect(&self, url: &Url) -> Result<Session, Error> {
        self.client.connect(url).await.map(Session).map_err(Error::from)
    }

    /// Accept an incoming connection.
    pub async fn accept(&mut self) -> Result<Option<Session>, Error> {
        match self.server.accept().await {
            Some(session) => Ok(Some(
                session.ok().await.map(Session).map_err(|e| Error::Write(e.into()))?,
            )),
            None => Ok(None),
        }
    }

    /// Key used by this endpoint.
    pub fn key(&self) -> Arc<dyn SigningKey> {
        self.key.key.clone()
    }
}

/// A WebTransport Session, able to accept/create streams and send/recv datagrams.
///
/// The session can be cloned to create multiple handles.
/// The session will be closed with on drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session(web_transport::Session);

impl Session {
    /// Block until the peer creates a new unidirectional stream.
    ///
    /// Won't return None unless the connection is closed.
    pub async fn accept_uni(&mut self) -> Result<RecvStream, Error> {
        let stream = self.0.accept_uni().await?;
        Ok(RecvStream::new(stream))
    }

    /// Block until the peer creates a new bidirectional stream.
    pub async fn accept_bi(&mut self) -> Result<(SendStream, RecvStream), Error> {
        let (s, r) = self.0.accept_bi().await?;
        Ok((SendStream::new(s), RecvStream::new(r)))
    }

    /// Open a new bidirectional stream.
    ///
    /// May block when there are too many concurrent streams.
    pub async fn open_bi(&mut self) -> Result<(SendStream, RecvStream), Error> {
        Ok(self
            .0
            .open_bi()
            .await
            .map(|(s, r)| (SendStream::new(s), RecvStream::new(r)))?)
    }

    /// Open a new unidirectional stream.
    ///
    /// May block when there are too many concurrent streams.
    pub async fn open_uni(&mut self) -> Result<SendStream, Error> {
        Ok(self.0.open_uni().await.map(SendStream::new)?)
    }

    /// Send a datagram over the network.
    ///
    /// QUIC datagrams may be dropped for any reason:
    /// - Network congestion.
    /// - Random packet loss.
    /// - Payload is larger than `max_datagram_size()`
    /// - Peer is not receiving datagrams.
    /// - Peer has too many outstanding datagrams.
    /// - ???
    pub fn send_datagram(&mut self, payload: Bytes) -> Result<(), Error> {
        Ok(self.0.send_datagram(payload)?)
    }

    /// The maximum size of a datagram that can be sent.
    pub async fn max_datagram_size(&self) -> usize {
        self.0.max_datagram_size()
    }

    /// Receive a datagram over the network.
    pub async fn recv_datagram(&mut self) -> Result<Bytes, Error> {
        Ok(self.0.read_datagram().await?)
    }

    /// Close the connection immediately with a code and reason.
    pub fn close(&mut self, code: u32, reason: &str) {
        self.0.close(code, reason.as_bytes())
    }

    /// Block until the connection is closed.
    pub async fn closed(&self) -> Error {
        self.0.closed().await.into()
    }
}

/// An outgoing stream of bytes to the peer.
///
/// QUIC streams have flow control, which means the send rate is limited by the peer's receive window.
/// The stream will be closed with a graceful FIN when dropped.
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

/// A WebTransport error.
///
/// The source can either be a session error or a stream error.
#[derive(Debug, thiserror::Error, Clone)]
pub enum Error {
    #[error("session error: {0}")]
    Session(#[from] web_transport::SessionError),

    #[error("client error: {0}")]
    Client(#[from] web_transport::ClientError),

    #[error("write error: {0}")]
    Write(web_transport::WriteError),

    #[error("read error: {0}")]
    Read(web_transport::ReadError),
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
