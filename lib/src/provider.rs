use web_transport_quinn::quinn::rustls;

use rustls::{crypto::WebPkiSupportedAlgorithms, pki_types::alg_id};
use tracing::trace;

/// Install a default [`CryptoProvider`] specialised for Mushi applications.
///
/// This uses _ring_ and specifically disallows all uses of RSA. If you require RSA for other TLS
/// or _ring_ applications, either use the `with_provider` variants of builders for these, or
/// install [`rustls::crypto::ring::default_provider()`] directly instead.
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
