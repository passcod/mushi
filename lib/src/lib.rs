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

use tokio::sync::{Mutex, watch};

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
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
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

/// Encode DER as PEM, 64 characters to a line as the format requires.
fn pem_encode(label: &str, der: &[u8]) -> String {
    let body = BASE64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        // UNWRAP: base64 output is ASCII, so every chunk is valid UTF-8
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
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

    /// The certificate as PEM, for storing across restarts.
    ///
    /// Persisting matters more than it looks: the hash covers the certificate, not the key, so a
    /// device that reissues on boot comes back with a hash nobody has published yet. It is then
    /// unreachable until it republishes *and* that propagates — and it can't even do that if the
    /// backchannel happens to be down. A device that reloads the certificate it was already
    /// serving is reachable immediately and can republish at leisure.
    ///
    /// Store [`Certificate::key_pem`] alongside this; both are needed to reload.
    pub fn to_pem(&self) -> String {
        pem_encode("CERTIFICATE", &self.der)
    }

    /// The private key as PEM.
    ///
    /// This is secret material. It is the counterpart to [`Certificate::to_pem`] and both are
    /// needed by [`Certificate::from_pem`].
    pub fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    /// Reload a stored certificate and its key.
    ///
    /// Validity is read back out of the certificate, so [`Certificate::not_after`] and
    /// [`Certificate::is_browser_valid`] mean the same thing for a reloaded certificate as for a
    /// freshly issued one.
    ///
    /// This is also how to adopt a certificate issued elsewhere — if your backend mints
    /// certificates and provisions them to devices, it already knows the hash before the device
    /// does, and there is nothing to report back.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, Error> {
        let der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|e| Error::MalformedCertificate(e.to_string()))?;

        let key = KeyPair::from_pem(key_pem)?;
        let scheme = BROWSER_SIGSCHEMES
            .iter()
            .copied()
            .find(|(_, alg)| key.is_compatible(alg))
            .ok_or(Error::UnsupportedKey)?;

        let (_, parsed) = x509_parser::parse_x509_certificate(&der)
            .map_err(|e| Error::MalformedCertificate(e.to_string()))?;
        let not_before = parsed.validity().not_before.to_datetime();
        let not_after = parsed.validity().not_after.to_datetime();

        let hash = CertHash::of(&der);
        Ok(Self {
            der,
            key: Arc::new(key),
            scheme,
            hash,
            not_before,
            not_after,
        })
    }

    /// When rotation should begin: `lead` before expiry.
    ///
    /// `lead` needs to cover issuing, publishing, and waiting for that to propagate, with room to
    /// retry if the backchannel is down. Erring long costs nothing.
    pub fn renew_at(&self, lead: Duration) -> OffsetDateTime {
        self.not_after - lead
    }

    /// Whether [`Certificate::renew_at`] has passed.
    pub fn needs_renewal(&self, lead: Duration) -> bool {
        OffsetDateTime::now_utc() >= self.renew_at(lead)
    }

    /// Refuse a certificate no browser could accept, so it fails here rather than at handshake.
    fn ensure_servable(&self) -> Result<(), Error> {
        if OffsetDateTime::now_utc() >= self.not_after {
            return Err(Error::CertificateExpired(self.not_after));
        }
        Ok(())
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

/// The certificates a server is serving, publishing, and retiring.
///
/// A server serves exactly one certificate at a time — nothing in the handshake says which hash
/// the browser pinned, so it can't choose per-connection. The overlap that makes rotation seamless
/// therefore lives entirely in *publication*: a browser accepts a list, so both hashes must be in
/// what your backend serves **before** the served certificate changes underneath it.
///
/// That gives one invariant, and this type exists to make it hard to break:
///
/// > A certificate must be published, and that publication must have propagated, before it is
/// > served.
///
/// So there are three slots. [`stage`](Rotation::stage) makes a certificate publishable without
/// serving it; [`promote`](Rotation::promote) starts serving it once you know the hash is out
/// there. The one it displaces stays published as `previous`, so a rollback or a stale snapshot
/// still connects, until you [`retire_previous`](Rotation::retire_previous).
///
/// Nothing here runs on a timer. Mushi can't see your backchannel, so it can't know whether a
/// publication landed, and a schedule that assumes it did would be guessing. You drive it;
/// [`Rotation::retire_previous_at`] and [`Certificate::needs_renewal`] tell you when.
///
/// ```no_run
/// # async fn rotate(
/// #     rotation: &mushi::Rotation,
/// #     identity: &mushi::Identity,
/// #     publish: impl AsyncFn(String) -> Result<(), mushi::Error>,
/// # ) -> Result<(), mushi::Error> {
/// rotation.stage(identity.issue(mushi::DEFAULT_VALIDITY)?)?;
/// publish(rotation.published_sri()).await?; // only proceed once this is confirmed
/// rotation.promote()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Rotation {
    state: RwLock<RotationState>,
    published: watch::Sender<String>,
}

#[derive(Debug)]
struct RotationState {
    previous: Option<Certificate>,
    current: Certificate,
    current_key: Arc<CertifiedKey>,
    staged: Option<Certificate>,
    promoted_at: Option<OffsetDateTime>,
}

impl RotationState {
    /// Every hash that should be published, most likely to match first.
    fn published(&self) -> Vec<CertHash> {
        let mut out = vec![self.current.hash.clone()];
        for cert in [self.staged.as_ref(), self.previous.as_ref()].into_iter().flatten() {
            if !out.contains(&cert.hash) {
                out.push(cert.hash.clone());
            }
        }
        out
    }
}

impl Rotation {
    /// Start a rotation serving `current`.
    pub fn new(current: Certificate) -> Result<Self, Error> {
        let current_key = Arc::new(current.certified_key()?);
        let state = RotationState {
            previous: None,
            current,
            current_key,
            staged: None,
            promoted_at: None,
        };
        let (published, _) = watch::channel(CertHash::set_to_sri(&state.published()));
        Ok(Self {
            state: RwLock::new(state),
            published,
        })
    }

    // UNWRAP (throughout): the lock guards plain data and nothing panics while it is held, so it
    // can only be poisoned by a panic that never happens.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, RotationState> {
        self.state.read().unwrap()
    }

    /// The certificate being served.
    pub fn current(&self) -> Certificate {
        self.read().current.clone()
    }

    /// The certificate queued to be served next, if any.
    pub fn staged(&self) -> Option<Certificate> {
        self.read().staged.clone()
    }

    /// The certificate most recently displaced, still published, if any.
    pub fn previous(&self) -> Option<Certificate> {
        self.read().previous.clone()
    }

    /// Every hash that should currently be published.
    pub fn published(&self) -> Vec<CertHash> {
        self.read().published()
    }

    /// Every hash that should currently be published, as one SRI string.
    ///
    /// This is the whole payload your backchannel needs to carry.
    pub fn published_sri(&self) -> String {
        self.published.borrow().clone()
    }

    /// Observe the published set, which changes on every staging, promotion, and retirement.
    ///
    /// Use this to drive publication reactively rather than polling — it also fires for changes
    /// made anywhere else, so a single subscriber sees everything.
    pub fn watch(&self) -> watch::Receiver<String> {
        self.published.subscribe()
    }

    /// Queue a certificate to be served next.
    ///
    /// It is published from this point but **not** served: call [`Rotation::promote`] once you
    /// know the hash has reached the browsers. Staging again replaces whatever was staged before.
    pub fn stage(&self, next: Certificate) -> Result<(), Error> {
        next.ensure_servable()?;
        self.update(|state| {
            state.staged = Some(next);
            Ok(())
        })
    }

    /// Serve the staged certificate.
    ///
    /// The one it displaces becomes `previous` and stays published until
    /// [`Rotation::retire_previous`]. Errors with [`Error::NothingStaged`] if nothing is staged.
    pub fn promote(&self) -> Result<Certificate, Error> {
        let mut promoted = None;
        self.update(|state| {
            let next = state.staged.take().ok_or(Error::NothingStaged)?;
            next.ensure_servable()?;

            state.current_key = Arc::new(next.certified_key()?);
            let displaced = std::mem::replace(&mut state.current, next.clone());
            state.previous = Some(displaced);
            state.promoted_at = Some(OffsetDateTime::now_utc());
            promoted = Some(next);
            Ok(())
        })?;
        // UNWRAP: update() returned Ok, so the closure ran to completion and set this
        Ok(promoted.unwrap())
    }

    /// Serve a certificate immediately, with no staging step.
    ///
    /// Only correct when the hash is *already* published — typically because your backend issued
    /// the certificate and so knew its hash before the device did. Otherwise use
    /// [`stage`](Rotation::stage) and [`promote`](Rotation::promote), which enforce the ordering.
    pub fn replace(&self, cert: Certificate) -> Result<(), Error> {
        cert.ensure_servable()?;
        self.update(|state| {
            state.current_key = Arc::new(cert.certified_key()?);
            let displaced = std::mem::replace(&mut state.current, cert);
            state.previous = Some(displaced);
            state.promoted_at = Some(OffsetDateTime::now_utc());
            Ok(())
        })
    }

    /// The earliest time it is safe to stop publishing the previous certificate.
    ///
    /// That is `propagation` after it was displaced. `propagation` is how long a published set
    /// takes to reach every browser — your backend's cache lifetime, plus however long a loaded
    /// page may sit on a snapshot before reconnecting. Mushi can't see any of that, which is why
    /// this computes a deadline rather than acting on one.
    ///
    /// `None` when there is nothing to retire.
    pub fn retire_previous_at(&self, propagation: Duration) -> Option<OffsetDateTime> {
        let state = self.read();
        state.previous.as_ref()?;
        state.promoted_at.map(|at| at + propagation)
    }

    /// Stop publishing the previous certificate.
    ///
    /// Returns it, or `None` if there wasn't one. Retiring early strands any browser still holding
    /// a snapshot from before the promotion, so consult [`Rotation::retire_previous_at`] first.
    pub fn retire_previous(&self) -> Option<Certificate> {
        let mut retired = None;
        // The closure is infallible, so this cannot fail.
        let _ = self.update(|state| {
            retired = state.previous.take();
            Ok(())
        });
        retired
    }

    /// Retire the previous certificate if [`Rotation::retire_previous_at`] has passed.
    ///
    /// The whole of the manual dance in one call, for a loop that ticks periodically.
    pub fn retire_previous_if_due(&self, propagation: Duration) -> Option<Certificate> {
        match self.retire_previous_at(propagation) {
            Some(due) if OffsetDateTime::now_utc() >= due => self.retire_previous(),
            _ => None,
        }
    }

    /// Apply a change and republish if the resulting set differs.
    fn update<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut RotationState) -> Result<(), Error>,
    {
        let sri = {
            // UNWRAP: see the note on read()
            let mut state = self.state.write().unwrap();
            f(&mut state)?;
            CertHash::set_to_sri(&state.published())
        };

        // send_if_modified keeps the watch from waking subscribers for a no-op change.
        self.published.send_if_modified(|current| {
            if *current == sri {
                false
            } else {
                *current = sri;
                true
            }
        });
        Ok(())
    }
}

impl ResolvesServerCert for Rotation {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.read().current_key.clone())
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
        let rotation = Arc::new(Rotation::new(cert)?);

        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(rotation.clone());
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
            rotation,
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
    rotation: Arc<Rotation>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("endpoint", &self.endpoint)
            .field("cert", &self.rotation.current())
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
        self.rotation.current()
    }

    /// The certificates this server is serving, publishing, and retiring.
    ///
    /// This is where rotation happens. See [`Rotation`].
    pub fn rotation(&self) -> &Arc<Rotation> {
        &self.rotation
    }

    /// Replace the certificate served to new connections, with no staging step.
    ///
    /// Shorthand for [`Rotation::replace`], and correct only when the hash is already published.
    /// Existing sessions are untouched.
    pub fn set_certificate(&self, cert: Certificate) -> Result<(), Error> {
        self.rotation.replace(cert)
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

    #[error("malformed certificate: {0}")]
    MalformedCertificate(String),

    #[error("certificate expired at {0}")]
    CertificateExpired(OffsetDateTime),

    #[error("no certificate is staged")]
    NothingStaged,

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
