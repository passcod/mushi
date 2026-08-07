//! End-to-end tests against a client that pins the certificate hash, exactly as a browser does.

use std::sync::{Arc, LazyLock};

use mushi::{
    Certificate, DEFAULT_VALIDITY, Identity, Server, Session, StatusCode, Url, quinn,
    rustls::{
        self, DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{CryptoProvider, verify_tls13_signature},
        pki_types::{CertificateDer, ServerName, UnixTime},
    },
    web_transport::{ALPN, Client, crypto},
};
use tokio::task::{JoinHandle, spawn};

static SETUP: LazyLock<()> = LazyLock::new(|| {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
});

/// Accepts a server certificate if its SHA-256 is one we were given, and performs no chain or name
/// validation at all — which is what a browser does with `serverCertificateHashes`.
///
/// Upstream ships an equivalent, but its builder binds `[::]:0` unconditionally, so we construct
/// the endpoint ourselves to stay usable on hosts without IPv6.
#[derive(Debug)]
struct PinnedHashes {
    provider: Arc<CryptoProvider>,
    allowed: Vec<Vec<u8>>,
}

impl ServerCertVerifier for PinnedHashes {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let hash = crypto::sha256(&self.provider, end_entity);
        if self.allowed.iter().any(|a| a == hash.as_ref()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate hash not pinned".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        unimplemented!("WebTransport is TLS 1.3 only")
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Bind to IPv4 loopback: not every CI runner (or container) has IPv6 configured.
fn server() -> (Server, Certificate) {
    let id = Identity::generate().unwrap();
    let cert = id.issue(DEFAULT_VALIDITY).unwrap();
    let server = Server::builder()
        .with_addr("127.0.0.1:0".parse().unwrap())
        .with_certificate(cert.clone())
        .unwrap();
    (server, cert)
}

/// A client that trusts exactly the hashes given, the way a page passes `serverCertificateHashes`.
fn client_pinning(certs: &[&Certificate]) -> Client {
    let provider = crypto::default_provider();
    let verifier = Arc::new(PinnedHashes {
        provider: provider.clone(),
        allowed: certs.iter().map(|c| c.hash().value.clone()).collect(),
    });

    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.as_bytes().to_vec()];

    let config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();

    Client::new(endpoint, config)
}

fn url(server: &Server, path: &str) -> Url {
    let addr = server.local_addr().unwrap();
    Url::parse(&format!("https://{addr}{path}")).unwrap()
}

/// Accept every request, handing the session back.
fn serve(server: Server) -> (JoinHandle<()>, tokio::sync::mpsc::Receiver<Session>) {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let task = spawn(async move {
        while let Some(req) = server.accept().await {
            let Ok(session) = req.ok().await else {
                continue;
            };
            if tx.send(session).await.is_err() {
                break;
            }
        }
    });
    (task, rx)
}

#[tokio::test]
async fn connects_when_the_hash_matches() {
    *SETUP;

    let (server, cert) = server();
    let target = url(&server, "/");
    let client = client_pinning(&[&cert]);
    let (task, mut sessions) = serve(server);

    let session = client.connect(target).await.unwrap();
    let accepted = sessions.recv().await.unwrap();

    // Prove the session is actually live, not merely handed over.
    session.send_datagram("hello".as_bytes().into()).unwrap();
    assert_eq!(&accepted.recv_datagram().await.unwrap()[..], b"hello");
    task.abort();
}

#[tokio::test]
async fn rejects_when_the_hash_does_not_match() {
    *SETUP;

    let (server, _cert) = server();
    let target = url(&server, "/");

    // A different certificate entirely: the client should refuse the handshake.
    let other = Identity::generate()
        .unwrap()
        .issue(DEFAULT_VALIDITY)
        .unwrap();
    let client = client_pinning(&[&other]);
    let (task, _sessions) = serve(server);

    client.connect(target).await.unwrap_err();
    task.abort();
}

#[tokio::test]
async fn accepts_any_of_several_pinned_hashes() {
    *SETUP;

    let (server, cert) = server();
    let target = url(&server, "/");

    // Publishing current and next together is what makes rotation seamless.
    let next = Identity::generate()
        .unwrap()
        .issue(DEFAULT_VALIDITY)
        .unwrap();
    let client = client_pinning(&[&next, &cert]);
    let (task, mut sessions) = serve(server);

    client.connect(target).await.unwrap();
    sessions.recv().await.unwrap();
    task.abort();
}

#[tokio::test]
async fn rotation_swaps_the_served_certificate() {
    *SETUP;

    let (server, first) = server();
    let target = url(&server, "/");

    let id = Identity::generate().unwrap();
    let second = id.issue(DEFAULT_VALIDITY).unwrap();
    server.set_certificate(second.clone()).unwrap();
    assert_eq!(server.certificate().hash(), second.hash());

    let (task, mut sessions) = serve(server);

    // The new hash works...
    client_pinning(&[&second])
        .connect(target.clone())
        .await
        .unwrap();
    sessions.recv().await.unwrap();

    // ...and the old one no longer does.
    client_pinning(&[&first]).connect(target).await.unwrap_err();
    task.abort();
}

#[tokio::test]
async fn routes_and_rejects_on_the_path() {
    *SETUP;

    let (server, cert) = server();
    let allowed = url(&server, "/allowed");
    let denied = url(&server, "/denied");

    let task = spawn(async move {
        while let Some(req) = server.accept().await {
            // The path is the only part of the handshake a browser controls.
            if req.path() == "/allowed" {
                let _ = req.ok().await;
            } else {
                let _ = req.reject(StatusCode::NOT_FOUND).await;
            }
        }
    });

    client_pinning(&[&cert]).connect(allowed).await.unwrap();
    client_pinning(&[&cert]).connect(denied).await.unwrap_err();
    task.abort();
}

#[tokio::test]
async fn exchanges_datagrams_and_streams() {
    *SETUP;

    let (server, cert) = server();
    let target = url(&server, "/");
    let client = client_pinning(&[&cert]);
    let (task, mut sessions) = serve(server);

    let client_session = client.connect(target).await.unwrap();
    let server_session = sessions.recv().await.unwrap();

    // Datagram, client to server.
    client_session
        .send_datagram("hello".as_bytes().into())
        .unwrap();
    assert_eq!(&server_session.recv_datagram().await.unwrap()[..], b"hello");

    // Bidirectional stream, client to server and back.
    let (mut cs, mut cr) = client_session.open_bi().await.unwrap();
    cs.write_all(b"ping").await.unwrap();
    let (mut ss, mut sr) = server_session.accept_bi().await.unwrap();
    assert_eq!(&sr.read(64).await.unwrap().unwrap()[..], b"ping");
    ss.write(b"pong").await.unwrap();
    let mut buf = [0u8; 4];
    cr.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");

    // Unidirectional stream, server pushing to the client unprompted.
    let mut push = server_session.open_uni().await.unwrap();
    push.write(b"push").await.unwrap();
    push.finish().unwrap();
    let mut incoming = client_session.accept_uni().await.unwrap();
    assert_eq!(&incoming.read_to_end(64).await.unwrap()[..], b"push");

    task.abort();
}

#[tokio::test]
async fn a_rotation_overlap_is_seamless_for_a_browser_holding_both_hashes() {
    *SETUP;

    let (server, first) = server();
    let target = url(&server, "/");
    let rotation = server.rotation().clone();

    let second = Identity::generate()
        .unwrap()
        .issue(DEFAULT_VALIDITY)
        .unwrap();
    rotation.stage(second.clone()).unwrap();

    let (task, mut sessions) = serve(server);

    // A page that fetched the published set now holds both hashes.
    let both = [&first, &second];

    // Still serving the first, so that is what matches.
    client_pinning(&both).connect(target.clone()).await.unwrap();
    sessions.recv().await.unwrap();

    rotation.promote().unwrap();

    // Now serving the second — the same page connects without refetching anything.
    client_pinning(&both).connect(target.clone()).await.unwrap();
    sessions.recv().await.unwrap();

    // A page holding only the pre-rotation snapshot cannot, which is why the previous hash stays
    // published until it has had time to propagate.
    client_pinning(&[&first])
        .connect(target.clone())
        .await
        .unwrap_err();

    // And one holding only the post-rotation snapshot can.
    client_pinning(&[&second]).connect(target).await.unwrap();
    sessions.recv().await.unwrap();

    task.abort();
}

#[tokio::test]
async fn a_reloaded_certificate_serves_the_hash_that_was_already_published() {
    *SETUP;

    let original = Identity::generate()
        .unwrap()
        .issue(DEFAULT_VALIDITY)
        .unwrap();
    let published = original.hash().clone();

    // Simulate a restart: all the device kept was the PEM pair on disk.
    let reloaded =
        Certificate::from_pem(&original.to_pem(), &original.key_pem()).unwrap();
    drop(original);

    let server = Server::builder()
        .with_addr("127.0.0.1:0".parse().unwrap())
        .with_certificate(reloaded.clone())
        .unwrap();
    let target = url(&server, "/");
    let (task, mut sessions) = serve(server);

    // The hash published before the restart still matches, so the device is reachable at once.
    assert_eq!(reloaded.hash(), &published);
    client_pinning(&[&reloaded]).connect(target).await.unwrap();
    sessions.recv().await.unwrap();

    task.abort();
}
