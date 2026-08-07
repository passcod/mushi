//! Certificate issuance, and the constraints browsers put on it.

use mushi::{
    BROWSER_SIGSCHEMES, CertHash, DEFAULT_VALIDITY, Error, Identity, MAX_VALIDITY,
    SIGSCHEME_ECDSA256,
};
use time::{Duration, OffsetDateTime};

#[test]
fn generates_p256_by_default() {
    let id = Identity::generate().unwrap();
    assert_eq!(id.scheme(), SIGSCHEME_ECDSA256);
    assert!(BROWSER_SIGSCHEMES.contains(&id.scheme()));
}

#[test]
fn roundtrips_through_pem() {
    let id = Identity::generate().unwrap();
    let pem = id.serialize_pem();

    let loaded = Identity::from_pem(&pem).unwrap();
    assert_eq!(loaded.scheme(), id.scheme());
    assert_eq!(loaded.public_key_pem(), id.public_key_pem());
}

#[test]
fn issues_a_browser_valid_certificate() {
    let id = Identity::generate().unwrap();
    let cert = id.issue(DEFAULT_VALIDITY).unwrap();

    assert!(cert.is_browser_valid());
    assert!(cert.is_valid_at(OffsetDateTime::now_utc()));
    assert!(cert.not_after() - cert.not_before() < MAX_VALIDITY);
}

#[test]
fn certificate_is_backdated_for_clock_skew() {
    let id = Identity::generate().unwrap();
    let cert = id.issue(DEFAULT_VALIDITY).unwrap();

    // A device whose clock trails the browser's must still be reachable.
    assert!(cert.not_before() < OffsetDateTime::now_utc());
    assert!(cert.is_valid_at(OffsetDateTime::now_utc() - Duration::minutes(2)));
}

#[test]
fn rejects_validity_browsers_would_refuse() {
    let id = Identity::generate().unwrap();

    // Under two weeks, per the WebTransport spec.
    assert!(matches!(
        id.issue(MAX_VALIDITY),
        Err(Error::ValidityTooLong(_))
    ));
    assert!(matches!(
        id.issue(MAX_VALIDITY + Duration::days(1)),
        Err(Error::ValidityTooLong(_))
    ));
    assert!(matches!(
        id.issue(Duration::ZERO),
        Err(Error::ValidityTooShort(_))
    ));

    // Just under the limit is fine.
    assert!(
        id.issue(MAX_VALIDITY - Duration::seconds(1))
            .is_ok()
    );
}

#[test]
fn expired_certificate_is_not_browser_valid() {
    let id = Identity::generate().unwrap();
    let cert = id.issue(Duration::minutes(1)).unwrap();

    // Issuance backdates by five minutes, so a one-minute certificate is already expired.
    assert!(!cert.is_browser_valid());
    assert!(!cert.is_valid_at(OffsetDateTime::now_utc()));
}

#[test]
fn hash_is_sha256_of_the_der() {
    let id = Identity::generate().unwrap();
    let cert = id.issue(DEFAULT_VALIDITY).unwrap();

    let hash = cert.hash();
    assert_eq!(hash.algorithm, "sha-256");
    assert_eq!(hash.value.len(), 32);
    assert_eq!(hash.to_hex().len(), 64);
    assert_eq!(&CertHash::of(cert.der()), hash);
}

#[test]
fn rotating_changes_the_hash_even_on_the_same_key() {
    let id = Identity::generate().unwrap();
    let first = id.issue(DEFAULT_VALIDITY).unwrap();
    let second = id.issue(DEFAULT_VALIDITY).unwrap();

    // This is why the hash has to be republished on every rotation, not just on rekey.
    assert_ne!(first.hash(), second.hash());
}
