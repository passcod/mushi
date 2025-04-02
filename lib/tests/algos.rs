use std::sync::{Arc, LazyLock};

use mushi::{AllowAllConnections, Endpoint, EndpointKey, Error, Session};
use tokio::task::{JoinHandle, spawn};

static SETUP: LazyLock<()> = LazyLock::new(|| {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    mushi::install_crypto_provider();
});

#[tokio::test]
async fn both_ed25519() {
    *SETUP;

    let key1 = EndpointKey::generate().unwrap();
    let key2 = EndpointKey::generate().unwrap();

    let end1 = Endpoint::new("[::1]:0", key1, Arc::new(AllowAllConnections), None).unwrap();
    let end2 = Endpoint::new("[::1]:0", key2, Arc::new(AllowAllConnections), None).unwrap();

    let addr = end2.local_addr().unwrap();

    let task: JoinHandle<Result<(), Error>> = spawn(async move {
        if let Some(sesh) = end2.accept().await {
            let sesh = sesh?;
            sesh.closed().await?;
        }

        Ok(())
    });

    end1.connect(addr).await.unwrap();
    task.abort();
}

#[tokio::test]
async fn both_ecdsa256() {
    *SETUP;

    let key1 = EndpointKey::generate_for(mushi::SIGSCHEME_ECDSA256).unwrap();
    let key2 = EndpointKey::generate_for(mushi::SIGSCHEME_ECDSA256).unwrap();

    let end1 = Endpoint::new("[::1]:0", key1, Arc::new(AllowAllConnections), None).unwrap();
    let end2 = Endpoint::new("[::1]:0", key2, Arc::new(AllowAllConnections), None).unwrap();

    let addr = end2.local_addr().unwrap();

    let task: JoinHandle<Result<(), Error>> = spawn(async move {
        if let Some(sesh) = end2.accept().await {
            let sesh = sesh?;
            sesh.closed().await?;
        }

        Ok(())
    });

    end1.connect(addr).await.unwrap();
    task.abort();
}

#[tokio::test]
async fn both_ecdsa384() {
    *SETUP;

    let key1 = EndpointKey::generate_for(mushi::SIGSCHEME_ECDSA384).unwrap();
    let key2 = EndpointKey::generate_for(mushi::SIGSCHEME_ECDSA384).unwrap();

    let end1 = Endpoint::new("[::1]:0", key1, Arc::new(AllowAllConnections), None).unwrap();
    let end2 = Endpoint::new("[::1]:0", key2, Arc::new(AllowAllConnections), None).unwrap();

    let addr = end2.local_addr().unwrap();

    let task: JoinHandle<Result<(), Error>> = spawn(async move {
        if let Some(sesh) = end2.accept().await {
            let sesh = sesh?;
            sesh.closed().await?;
        }

        Ok(())
    });

    end1.connect(addr).await.unwrap();
    task.abort();
}

#[tokio::test]
async fn ecdsa256_ecdsa384() {
    *SETUP;

    let key1 = EndpointKey::generate_for(mushi::SIGSCHEME_ECDSA256).unwrap();
    let key2 = EndpointKey::generate_for(mushi::SIGSCHEME_ECDSA384).unwrap();

    let end1 = Endpoint::new("[::1]:0", key1, Arc::new(AllowAllConnections), None).unwrap();
    let end2 = Endpoint::new("[::1]:0", key2, Arc::new(AllowAllConnections), None).unwrap();

    let addr = end2.local_addr().unwrap();

    let task: JoinHandle<Result<(), Error>> = spawn(async move {
        if let Some(sesh) = end2.accept().await {
            let sesh = sesh?;
            sesh.closed().await?;
        }

        Ok(())
    });

    end1.connect(addr).await.unwrap();
    task.abort();
}

#[tokio::test]
async fn ecdsa256_ed25519() {
    *SETUP;

    let key1 = EndpointKey::generate_for(mushi::SIGSCHEME_ECDSA256).unwrap();
    let key2 = EndpointKey::generate_for(mushi::SIGSCHEME_ED25519).unwrap();

    let end1 = Endpoint::new("[::1]:0", key1, Arc::new(AllowAllConnections), None).unwrap();
    let end2 = Endpoint::new("[::1]:0", key2, Arc::new(AllowAllConnections), None).unwrap();

    let addr = end2.local_addr().unwrap();

    let task: JoinHandle<Result<(), Error>> = spawn(async move {
        if let Some(sesh) = end2.accept().await {
            let sesh = sesh?;
            sesh.closed().await?;
        }

        Ok(())
    });

    end1.connect(addr).await.unwrap();
    task.abort();
}

#[tokio::test]
async fn thousand_keys() {
    *SETUP;

    let mut n = 0;
    for _ in 0..1000 {
        n += EndpointKey::generate().unwrap().public_key_pem().len();
    }
    assert!(n > 0);
}
