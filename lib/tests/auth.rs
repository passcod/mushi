use std::sync::{Arc, LazyLock, Mutex};

use mushi::{
    AllowAllConnections, AllowConnection, CertificateError, Endpoint, EndpointKey, Error,
    SubjectPublicKeyInfoDer,
};
use tokio::task::{JoinHandle, spawn};

static SETUP: LazyLock<()> = LazyLock::new(|| {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    mushi::install_crypto_provider();
});

#[derive(Debug)]
struct AllowKeySet(Vec<EndpointKey>);

impl AllowConnection for AllowKeySet {
    fn allow_public_key(&self, key: SubjectPublicKeyInfoDer<'_>) -> Result<(), CertificateError> {
        if self.0.iter().any(|ek| *ek.public_key_der() == *key) {
            Ok(())
        } else {
            Err(CertificateError::ApplicationVerificationFailure)
        }
    }
}

#[tokio::test]
async fn keyset() {
    *SETUP;

    let key1 = EndpointKey::generate().unwrap();
    let key2 = EndpointKey::generate().unwrap();
    let key3 = EndpointKey::generate().unwrap();

    let allower = Arc::new(AllowKeySet(vec![key1.clone(), key2.clone()]));

    let end1 = Endpoint::new("[::1]:0", key1, allower.clone(), None).unwrap();
    let end2 = Endpoint::new("[::1]:0", key2, allower.clone(), None).unwrap();
    let end3 = Endpoint::new("[::1]:0", key3, allower, None).unwrap();

    let addr = end2.local_addr().unwrap();

    let task: JoinHandle<Result<(), Error>> = spawn(async move {
        while let Some(sesh) = end2.accept().await {
            let sesh = sesh?;
            sesh.closed().await?;
        }

        Ok(())
    });

    end1.connect(addr).await.unwrap();
    end3.connect(addr).await.unwrap_err();
    task.abort();
}

#[derive(Debug, Default)]
struct AllowSecondHit(Mutex<Vec<SubjectPublicKeyInfoDer<'static>>>);

impl AllowConnection for AllowSecondHit {
    fn allow_public_key(&self, key: SubjectPublicKeyInfoDer<'_>) -> Result<(), CertificateError> {
        let mut cache = self.0.lock().unwrap();
        if cache.iter().any(|ek| *ek == key) {
            Ok(())
        } else {
            cache.push(dbg!(key.into_owned()));
            Err(CertificateError::ApplicationVerificationFailure)
        }
    }
}

#[tokio::test]
async fn second_hit() {
    *SETUP;

    let key1 = EndpointKey::generate().unwrap();
    let key2 = EndpointKey::generate().unwrap();
    let key3 = EndpointKey::generate().unwrap();

    let allower = Arc::new(AllowAllConnections);

    let end2 = Endpoint::new("[::1]:0", key2, Arc::new(AllowSecondHit::default()), None).unwrap();
    let end1 = Endpoint::new("[::1]:0", key1, allower.clone(), None).unwrap();
    let end3 = Endpoint::new("[::1]:0", key3, allower, None).unwrap();

    let addr = end2.local_addr().unwrap();

    let task: JoinHandle<Result<(), Error>> = spawn(async move {
        while let Some(sesh) = end2.accept().await {
            let sesh = sesh?;
            sesh.closed().await?;
        }

        Ok(())
    });

    end1.connect(addr).await.unwrap_err();
    end3.connect(addr).await.unwrap_err();
    end3.connect(addr).await.unwrap();
    end1.connect(addr).await.unwrap();
    task.abort();
}
