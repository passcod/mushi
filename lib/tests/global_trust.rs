use std::sync::{Arc, LazyLock, Mutex};

use mushi::{
    CertificateError, Endpoint, EndpointOptions, Error, Key, Session, SubjectPublicKeyInfoDer,
};
use tokio::task::{JoinHandle, spawn};

static SETUP: LazyLock<()> = LazyLock::new(|| {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    mushi::install_crypto_provider();
});

#[tokio::test]
async fn keyset() {
    *SETUP;

    let key1 = Key::generate().unwrap();
    let key2 = Key::generate().unwrap();
    let key3 = Key::generate().unwrap();

    let keyset_opt = EndpointOptions {
        key_trust_policy: Arc::new({
            let keyset = [key1.clone(), key2.clone()];
            move |key| {
                if keyset.iter().any(|ek| *ek.public_key_der() == *key) {
                    Ok(())
                } else {
                    Err(CertificateError::ApplicationVerificationFailure)
                }
            }
        }),
        ..Default::default()
    };

    let end1 = Endpoint::new("[::1]:0", key1, keyset_opt.clone()).unwrap();
    let end2 = Endpoint::new("[::1]:0", key2, keyset_opt).unwrap();
    let end3 = Endpoint::new("[::1]:0", key3, Default::default()).unwrap();

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

#[tokio::test]
async fn second_hit() {
    *SETUP;

    let key1 = Key::generate().unwrap();
    let key2 = Key::generate().unwrap();
    let key3 = Key::generate().unwrap();

    let hitmap: Arc<Mutex<Vec<SubjectPublicKeyInfoDer<'static>>>> = Default::default();
    let secondhit_opt = EndpointOptions {
        key_trust_policy: Arc::new(move |key| {
            let mut cache = hitmap.lock().unwrap();
            if cache.iter().any(|ek| *ek == key) {
                Ok(())
            } else {
                cache.push(dbg!(key.into_owned()));
                Err(CertificateError::ApplicationVerificationFailure)
            }
        }),
        ..Default::default()
    };

    let end2 = Endpoint::new("[::1]:0", key2, secondhit_opt.clone()).unwrap();
    let end1 = Endpoint::new("[::1]:0", key1, secondhit_opt.clone()).unwrap();
    let end3 = Endpoint::new("[::1]:0", key3, secondhit_opt.clone()).unwrap();

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
