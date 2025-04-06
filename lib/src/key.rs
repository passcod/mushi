use std::sync::Arc;

use web_transport_quinn::quinn::rustls;

use rcgen::{CertificateParams, DistinguishedName as Dn, DnType, KeyPair};
use rustls::{
    SignatureScheme,
    client::ResolvesClientCert,
    crypto::CryptoProvider,
    pki_types::PrivateKeyDer,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use time::{Duration, OffsetDateTime};

/// A key pair that identifies and authenticates an [`Endpoint`].
#[derive(Debug, Clone)]
pub struct Key {
    pub(crate) scheme: SigScheme,
    pub(crate) key: Arc<KeyPair>,

    /// How long certificates should be valid for. Defaults to 2 minutes.
    pub validity: Duration,
}

impl std::ops::Deref for Key {
    type Target = KeyPair;
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

/// A signature scheme for generating and using an [`Key`].
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

impl Key {
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
                provider,
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

impl ResolvesClientCert for Key {
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

impl ResolvesServerCert for Key {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.get_certificate()
    }
}
