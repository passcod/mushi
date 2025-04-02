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
async fn connection() {
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
async fn datagram() {
    *SETUP;

    let key1 = EndpointKey::generate().unwrap();
    let key2 = EndpointKey::generate().unwrap();

    let end1 = Endpoint::new("[::1]:0", key1, Arc::new(AllowAllConnections), None).unwrap();
    let end2 = Endpoint::new("[::1]:0", key2, Arc::new(AllowAllConnections), None).unwrap();

    let addr = end2.local_addr().unwrap();

    let task: JoinHandle<Result<(), Error>> = spawn(async move {
        if let Some(sesh) = end2.accept().await {
            let sesh = sesh?;
            let data = sesh.recv_datagram().await.unwrap();
            assert_eq!(data, "Hello");
            sesh.send_datagram("World".into()).unwrap();
            sesh.closed().await?;
        }

        Ok(())
    });

    let sesh = end1.connect(addr).await.unwrap();
    sesh.send_datagram("Hello".into()).unwrap();
    let data = sesh.recv_datagram().await.unwrap();
    assert_eq!(data, "World");
    sesh.close(0, "end");
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn unidi() {
    *SETUP;

    let key1 = EndpointKey::generate().unwrap();
    let key2 = EndpointKey::generate().unwrap();

    let end1 = Endpoint::new("[::1]:0", key1, Arc::new(AllowAllConnections), None).unwrap();
    let end2 = Endpoint::new("[::1]:0", key2, Arc::new(AllowAllConnections), None).unwrap();

    let addr = end2.local_addr().unwrap();

    let task: JoinHandle<Result<(), Error>> = spawn(async move {
        if let Some(sesh) = end2.accept().await {
            let sesh = sesh?;
            let data = sesh
                .accept_uni()
                .await
                .unwrap()
                .read(5)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(data, "Hello");
            sesh.open_uni()
                .await
                .unwrap()
                .write(b"World")
                .await
                .unwrap();
            sesh.closed().await?;
        }

        Ok(())
    });

    let sesh = end1.connect(addr).await.unwrap();
    sesh.open_uni()
        .await
        .unwrap()
        .write(b"Hello")
        .await
        .unwrap();
    let data = sesh
        .accept_uni()
        .await
        .unwrap()
        .read(5)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data, "World");
    sesh.close(0, "end");
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn bidi() {
    *SETUP;

    let key1 = EndpointKey::generate().unwrap();
    let key2 = EndpointKey::generate().unwrap();

    let end1 = Endpoint::new("[::1]:0", key1, Arc::new(AllowAllConnections), None).unwrap();
    let end2 = Endpoint::new("[::1]:0", key2, Arc::new(AllowAllConnections), None).unwrap();

    let addr = end2.local_addr().unwrap();

    let task: JoinHandle<Result<(), Error>> = spawn(async move {
        if let Some(sesh) = end2.accept().await {
            let sesh = sesh?;
            let (mut s, mut r) = sesh.accept_bi().await.unwrap();
            s.write(b"World").await.unwrap();
            let data = r.read(5).await.unwrap().unwrap();
            assert_eq!(data, "Hello");
            sesh.closed().await?;
        }

        Ok(())
    });

    let sesh = end1.connect(addr).await.unwrap();
    let (mut s, mut r) = sesh.open_bi().await.unwrap();
    s.write(b"Hello").await.unwrap();
    let data = r.read(5).await.unwrap().unwrap();
    assert_eq!(data, "World");
    sesh.close(0, "end");
    task.await.unwrap().unwrap();
}
