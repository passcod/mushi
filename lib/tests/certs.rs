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

#[test]
fn hash_round_trips_through_sri() {
    let cert = Identity::generate().unwrap().issue(DEFAULT_VALIDITY).unwrap();
    let hash = cert.hash();

    let sri = hash.to_sri();
    assert!(sri.starts_with("sha256-"));
    assert_eq!(sri, hash.to_string());
    assert_eq!(&CertHash::from_sri(&sri).unwrap(), hash);
    assert_eq!(&sri.parse::<CertHash>().unwrap(), hash);

    // SRI spells it `sha256`; the browser dictionary wants `sha-256`.
    assert_eq!(hash.algorithm, "sha-256");
}

#[test]
fn sri_digest_is_standard_base64() {
    let cert = Identity::generate().unwrap().issue(DEFAULT_VALIDITY).unwrap();
    let digest = cert.hash().to_sri();
    let digest = digest.strip_prefix("sha256-").unwrap();

    // URL-safe base64 would put '-' inside the digest and break splitting on the first one.
    assert!(!digest.contains('-'));
    assert!(!digest.contains('_'));
    // 32 bytes, padded.
    assert_eq!(digest.len(), 44);
    assert!(digest.ends_with('='));
}

#[test]
fn a_set_publishes_as_one_space_separated_string() {
    let id = Identity::generate().unwrap();
    let current = id.issue(DEFAULT_VALIDITY).unwrap();
    let staged = id.issue(DEFAULT_VALIDITY).unwrap();

    // SRI's "any of these matching is acceptable" is exactly the rotation overlap.
    let published = CertHash::set_to_sri(&[current.hash().clone(), staged.hash().clone()]);
    assert_eq!(published.split(' ').count(), 2);

    let parsed = CertHash::set_from_sri(&published).unwrap();
    assert_eq!(parsed, vec![current.hash().clone(), staged.hash().clone()]);
}

#[test]
fn sri_parsing_is_lenient_where_it_can_be() {
    let hash = Identity::generate()
        .unwrap()
        .issue(DEFAULT_VALIDITY)
        .unwrap()
        .hash()
        .clone();
    let sri = hash.to_sri();

    // Options suffix, per the SRI grammar.
    assert_eq!(CertHash::from_sri(&format!("{sri}?foo=bar")).unwrap(), hash);
    // Surrounding whitespace, and irregular spacing within a set.
    assert_eq!(CertHash::from_sri(&format!("  {sri} ")).unwrap(), hash);
    assert_eq!(
        CertHash::set_from_sri(&format!("\n{sri}   {sri}\t")).unwrap(),
        vec![hash.clone(), hash.clone()]
    );
    // Unpadded and URL-safe digests still decode.
    let unpadded = sri.trim_end_matches('=');
    assert_eq!(CertHash::from_sri(unpadded).unwrap(), hash);
}

#[test]
fn sri_parsing_rejects_what_it_should() {
    assert!(matches!(
        CertHash::from_sri("47DEQpj8HBSa"),
        Err(Error::MalformedHash(_))
    ));
    assert!(matches!(
        CertHash::from_sri("md5-47DEQpj8HBSa"),
        Err(Error::UnknownHashAlgorithm(_))
    ));
    assert!(matches!(
        CertHash::from_sri("sha256-not!valid!base64!"),
        Err(Error::MalformedHash(_))
    ));

    // A partly-unreadable set fails loudly: silently dropping a hash can strand a device.
    assert!(CertHash::set_from_sri("sha256-AAAA md5-BBBB").is_err());
}
