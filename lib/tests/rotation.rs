//! Persistence, and the publish-before-serve ordering that rotation depends on.

use mushi::{CertHash, DEFAULT_VALIDITY, Error, Identity, Rotation};
use time::{Duration, OffsetDateTime};

fn cert() -> mushi::Certificate {
    Identity::generate().unwrap().issue(DEFAULT_VALIDITY).unwrap()
}

#[test]
fn certificate_survives_a_restart() {
    let original = cert();
    let (cert_pem, key_pem) = (original.to_pem(), original.key_pem());

    let reloaded = mushi::Certificate::from_pem(&cert_pem, &key_pem).unwrap();

    // The whole point: same certificate, so the already-published hash still matches.
    assert_eq!(reloaded.hash(), original.hash());
    assert_eq!(reloaded.der(), original.der());
    assert!(reloaded.is_browser_valid());
}

#[test]
fn reloaded_validity_is_read_back_from_the_certificate() {
    let original = cert();
    let reloaded =
        mushi::Certificate::from_pem(&original.to_pem(), &original.key_pem()).unwrap();

    // Certificates store seconds, so allow for the sub-second part being dropped.
    assert!((reloaded.not_before() - original.not_before()).abs() < Duration::seconds(1));
    assert!((reloaded.not_after() - original.not_after()).abs() < Duration::seconds(1));
}

#[test]
fn reloading_rejects_mismatched_or_malformed_input() {
    let a = cert();
    let b = cert();

    assert!(matches!(
        mushi::Certificate::from_pem("not a pem", &a.key_pem()),
        Err(Error::MalformedCertificate(_))
    ));
    assert!(mushi::Certificate::from_pem(&a.to_pem(), "not a pem").is_err());

    // A certificate paired with the wrong key loads, but can't serve — the TLS layer rejects it.
    let mismatched = mushi::Certificate::from_pem(&a.to_pem(), &b.key_pem()).unwrap();
    assert!(Rotation::new(mismatched).is_err());
}

#[test]
fn renewal_is_due_a_lead_time_before_expiry() {
    let short = Identity::generate()
        .unwrap()
        .issue(Duration::hours(1))
        .unwrap();

    assert_eq!(
        short.renew_at(Duration::minutes(10)),
        short.not_after() - Duration::minutes(10)
    );
    assert!(!short.needs_renewal(Duration::minutes(10)));
    // A lead longer than the remaining life means renewal is already overdue.
    assert!(short.needs_renewal(Duration::hours(2)));
}

#[test]
fn staging_publishes_without_serving() {
    let current = cert();
    let next = cert();
    let rotation = Rotation::new(current.clone()).unwrap();

    assert_eq!(rotation.published(), vec![current.hash().clone()]);

    rotation.stage(next.clone()).unwrap();

    // Published, so browsers can learn it...
    assert!(rotation.published().contains(next.hash()));
    // ...but not served, which is the entire ordering guarantee.
    assert_eq!(rotation.current().hash(), current.hash());
    assert_eq!(rotation.staged().unwrap().hash(), next.hash());
}

#[test]
fn promoting_serves_the_staged_certificate_and_keeps_the_old_one_published() {
    let current = cert();
    let next = cert();
    let rotation = Rotation::new(current.clone()).unwrap();

    rotation.stage(next.clone()).unwrap();
    let promoted = rotation.promote().unwrap();

    assert_eq!(promoted.hash(), next.hash());
    assert_eq!(rotation.current().hash(), next.hash());
    assert!(rotation.staged().is_none());

    // The displaced one stays published so a stale snapshot or a rollback still connects.
    assert_eq!(rotation.previous().unwrap().hash(), current.hash());
    assert!(rotation.published().contains(current.hash()));
    assert!(rotation.published().contains(next.hash()));
}

#[test]
fn promoting_with_nothing_staged_is_an_error() {
    let rotation = Rotation::new(cert()).unwrap();
    assert!(matches!(rotation.promote(), Err(Error::NothingStaged)));
}

#[test]
fn an_expired_certificate_is_refused_rather_than_served() {
    let id = Identity::generate().unwrap();
    // Issuance backdates five minutes, so this one is already past its notAfter.
    let expired = id.issue(Duration::minutes(1)).unwrap();
    let rotation = Rotation::new(cert()).unwrap();

    assert!(matches!(
        rotation.stage(expired.clone()),
        Err(Error::CertificateExpired(_))
    ));
    assert!(matches!(
        rotation.replace(expired),
        Err(Error::CertificateExpired(_))
    ));
}

#[test]
fn retiring_is_manual_and_gated_on_propagation() {
    let current = cert();
    let next = cert();
    let rotation = Rotation::new(current.clone()).unwrap();

    // Nothing to retire before the first promotion.
    assert!(rotation.retire_previous_at(Duration::hours(1)).is_none());
    assert!(rotation.retire_previous().is_none());

    rotation.stage(next).unwrap();
    rotation.promote().unwrap();

    let due = rotation.retire_previous_at(Duration::hours(1)).unwrap();
    assert!(due > OffsetDateTime::now_utc());

    // Not due yet, so the helper leaves it alone and the hash stays published.
    assert!(rotation.retire_previous_if_due(Duration::hours(1)).is_none());
    assert!(rotation.published().contains(current.hash()));

    // Due, so it goes.
    let retired = rotation.retire_previous_if_due(Duration::ZERO).unwrap();
    assert_eq!(retired.hash(), current.hash());
    assert!(!rotation.published().contains(current.hash()));
    assert!(rotation.previous().is_none());
}

#[test]
fn published_set_is_deduplicated_and_current_first() {
    let current = cert();
    let rotation = Rotation::new(current.clone()).unwrap();

    // Staging what is already served must not publish the same hash twice.
    rotation.stage(current.clone()).unwrap();
    assert_eq!(rotation.published(), vec![current.hash().clone()]);

    let next = cert();
    rotation.stage(next.clone()).unwrap();
    let published = rotation.published();
    assert_eq!(published[0], *current.hash(), "current should come first");
    assert_eq!(published[1], *next.hash());
}

#[test]
fn published_sri_is_the_whole_backchannel_payload() {
    let current = cert();
    let next = cert();
    let rotation = Rotation::new(current.clone()).unwrap();
    rotation.stage(next.clone()).unwrap();

    let sri = rotation.published_sri();
    assert_eq!(CertHash::set_from_sri(&sri).unwrap(), rotation.published());
    assert_eq!(sri.split(' ').count(), 2);
}

#[tokio::test]
async fn watchers_see_every_change_to_the_published_set() {
    let rotation = Rotation::new(cert()).unwrap();
    let mut rx = rotation.watch();
    assert_eq!(*rx.borrow_and_update(), rotation.published_sri());

    let next = cert();
    rotation.stage(next.clone()).unwrap();
    rx.changed().await.unwrap();
    assert!(rx.borrow_and_update().contains(&next.hash().to_sri()));

    rotation.promote().unwrap();
    rx.changed().await.unwrap();

    rotation.retire_previous().unwrap();
    rx.changed().await.unwrap();
    assert_eq!(*rx.borrow_and_update(), next.hash().to_sri());
}

#[tokio::test]
async fn a_no_op_change_does_not_wake_watchers() {
    let current = cert();
    let rotation = Rotation::new(current.clone()).unwrap();
    let mut rx = rotation.watch();
    rx.borrow_and_update();

    // Staging the certificate already being served changes nothing publishable.
    rotation.stage(current).unwrap();
    assert!(!rx.has_changed().unwrap());
}
