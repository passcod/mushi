use pyo3::prelude::*;

#[pymodule(name = "pymushi")]
pub mod export {
    use std::{
        collections::HashMap,
        sync::{
            Arc, LazyLock,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use mushi::{
        AllowConnection, CertificateError, SigScheme, SubjectPublicKeyInfoDer, UnixTime,
        quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig},
        rcgen,
    };
    use pyo3::{
        prelude::*,
        types::{PyBool, PyDict, PyString},
    };
    use tokio::sync::Mutex;

    use crate::error::*;

    static SETUP: LazyLock<()> = LazyLock::new(mushi::install_crypto_provider);

    const SUPPORTED_SIGSCHEMES: &[SigScheme] = &[
        mushi::SIGSCHEME_ED25519,
        mushi::SIGSCHEME_ECDSA256,
        mushi::SIGSCHEME_ECDSA384,
    ];

    /// A key pair that identifies and authenticates an `Endpoint`.
    #[pyclass]
    #[derive(Debug, Clone)]
    pub struct EndpointKey(mushi::EndpointKey);

    #[pymethods]
    impl EndpointKey {
        /// Load a private key from a PEM-encoded PKCS#8 private key string.
        ///
        /// If the key is not ED25519 or ECDSA(256|384), this will error.
        #[new]
        fn new(private_key_pem: String) -> BResult<Self> {
            let kp = rcgen::KeyPair::from_pem(&private_key_pem)?;

            for scheme in SUPPORTED_SIGSCHEMES {
                if kp.is_compatible(scheme.1) {
                    return Ok(Self(mushi::EndpointKey::load(kp, *scheme)));
                }
            }

            Err(BError::UnsupportedKeyType(format!("{:?}", kp.algorithm())))
        }

        /// Serialize private key to PEM.
        fn private_key_pem(&self) -> String {
            self.0.serialize_pem()
        }

        /// Serialize public key to PEM.
        fn public_key_pem(&self) -> String {
            self.0.public_key_pem()
        }

        fn __str__(&self) -> String {
            format!("EndpointKey type={:?}", self.0.algorithm())
        }

        /// The validity of certificates generated by this key in seconds.
        #[getter]
        pub fn get_validity(&self) -> u32 {
            self.0.validity.whole_seconds().max(0).try_into().unwrap()
        }

        /// Set the validity of certificates generated by this key in seconds.
        ///
        /// Note that changing the validity of a key once it's used in an Endpoint does nothing.
        #[setter]
        pub fn set_validity(&mut self, seconds: u32) {
            self.0.validity = Duration::from_secs(seconds as _).try_into().unwrap();
        }

        /// Generate a certificate for this key.
        ///
        /// This is primarily used internally, but exposed for convenience if you're implementing the
        /// transport yourself and don't want to bother making certificates correctly.
        ///
        /// Returns the PEM-encoded certificate.
        fn make_certificate(&self) -> BResult<String> {
            Ok(self.0.make_certificate()?.pem())
        }

        /// Generate a new random key pair in the default scheme.
        #[staticmethod]
        fn generate() -> BResult<Self> {
            Ok(Self(mushi::EndpointKey::generate()?))
        }

        /// Generate a new random key pair in the given scheme.
        ///
        /// The argument must be one of `ed25519`, `ecdsa256`, `ecdsa384`.
        #[staticmethod]
        fn generate_for(scheme: String) -> BResult<Self> {
            let scheme = match scheme.as_str() {
                "ed25519" => mushi::SIGSCHEME_ED25519,
                "ecdsa256" => mushi::SIGSCHEME_ECDSA256,
                "ecdsa384" => mushi::SIGSCHEME_ECDSA384,
                unk => return Err(BError::UnsupportedKeyType(unk.to_string())),
            };

            Ok(Self(mushi::EndpointKey::generate_for(scheme)?))
        }
    }

    /// Trust policy for peers.
    #[pyclass]
    #[derive(Debug, Clone)]
    pub struct Allower(Arc<AllowerImpl>);

    #[derive(Debug)]
    pub struct AllowerImpl {
        allower: Py<PyAny>,
        client_auth: bool,
    }

    impl AllowConnection for AllowerImpl {
        fn allow_public_key(
            &self,
            key: SubjectPublicKeyInfoDer<'_>,
            now: UnixTime,
        ) -> std::result::Result<(), CertificateError> {
            let ret = Arc::new(AtomicBool::new(false));

            Python::with_gil(|py| {
                let value = self
                    .allower
                    .call1(py, (key.as_ref(), now.as_secs()))
                    .map_or(false, |r| {
                        r.downcast_bound::<PyBool>(py)
                            .map_or(false, |b| b.is_true())
                    });
                ret.store(value, Ordering::SeqCst);
            });

            if ret.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(CertificateError::ApplicationVerificationFailure)
            }
        }

        fn require_client_auth(&self) -> bool {
            self.client_auth
        }
    }

    #[pymethods]
    impl Allower {
        /// Define a new peer trust policy.
        ///
        /// `allow_public_key` must be a callable which takes two positional arguments: `key` (a
        /// bytearray) and `now` (an integer).
        ///
        /// `key` is the public key of the remote peer in DER format, but in general should be
        /// considered an opaque blob.
        ///
        /// `now` is a Unix timestamp (number of non-leap seconds since the epoch). If your trust
        /// logic involves time, you should use this as basis time to make calculations consistent.
        ///
        /// Return `True` to allow the peer to connect (or be connected to). Returning anything but
        /// a boolean true will be considered false. Exceptions will be lost to the ether.
        ///
        /// `require_client_auth` can be set to `false` for the rare case where incoming
        /// connections that cannot present a client certificate should be allowed. In that case,
        /// take care to implement an additional authorisation layer to restrict connections or
        /// resource access.
        #[new]
        fn new(
            allow_public_key: &Bound<'_, PyAny>,
            require_client_auth: Option<bool>,
        ) -> BResult<Self> {
            if !allow_public_key.is_callable() {
                return Err(BError::NotCallable("allow_public_key"));
            }

            let client_auth = require_client_auth.unwrap_or(true);
            Ok(Self(Arc::new(AllowerImpl {
                allower: allow_public_key.clone().unbind(),
                client_auth,
            })))
        }
    }

    /// The main entrypoint to create connections to, and accept connections from other Mushi peers.
    ///
    /// Generally, an application will have a single endpoint instance. This results in more optimal
    /// network behaviour, and as a single endpoint can have sessions to any number of peers, and each
    /// session supports many concurrent datagrams and streams, there’s little need (outside of
    /// testing) for multiple endpoints.
    ///
    /// Note that unlike the Rust API, there's no need to install a CryptoProvider before using this.
    #[pyclass]
    #[derive(Debug, Clone)]
    pub struct Endpoint(mushi::Endpoint);

    #[pymethods]
    impl Endpoint {
        /// Create and setup a Mushi peer.
        ///
        /// You must provide a local or unspecified address to bind the endpoint to. In most cases,
        /// `[::]:0` suffices: this binds to all IP interfaces and selects a random port. Use
        /// `localAddr()` to discover the randomly-assigned port.
        ///
        /// If `bind_to` resolves to multiple socket addresses, the first that succeeds creation of
        /// the socket will be used. `getaddrinfo()` or equivalent is used; to control DNS
        /// resolution, do that yourself and pass an IP address and port.
        ///
        /// `allower` is the trust policy for remote peers: incoming (client certificate) and
        /// outgoing (server certificate) peers will have their public key extracted and checked by
        /// the `Allower` instance.
        ///
        /// `cc` is the congestion control strategy for the QUIC state machine. One of `cubic`
        /// ([RFC
        /// 8312]), `newreno` ([RFC 6582]), or `bbr` ([IETF Draft]]. Defaults to `cubic`.
        ///
        /// [RFC 8312]: https://datatracker.ietf.org/doc/html/rfc8312 [RFC 6582]:
        /// https://datatracker.ietf.org/doc/html/rfc6582 [IETF Draft]:
        /// https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/02/
        #[new]
        fn new(
            bind_to: &str,
            key: &EndpointKey,
            allower: &Allower,
            py_kwargs: Option<&Bound<'_, PyDict>>,
        ) -> BResult<Self> {
            let cc: Arc<dyn ControllerFactory + Send + Sync + 'static> =
                match py_kwargs.map(|k| k.get_item("cc")).transpose()?.flatten() {
                    None => Arc::new(CubicConfig::default()),
                    Some(cc) => match cc
                        .downcast::<PyString>()?
                        .to_string_lossy()
                        .to_ascii_lowercase()
                        .as_str()
                    {
                        "cubic" => Arc::new(CubicConfig::default()),
                        "newreno" => Arc::new(NewRenoConfig::default()),
                        "bbr" => Arc::new(BbrConfig::default()),
                        unk => return Err(BError::UnknownCongestionControl(unk.into())),
                    },
                };

            *SETUP;

            Ok(Self(mushi::Endpoint::new(
                bind_to,
                key.0.clone(),
                allower.0.clone(),
                Some(cc),
            )?))
        }

        /// Get the local address the underlying socket is bound to.
        fn local_addr(&self) -> BResult<String> {
            Ok(self.0.local_addr().map(|addr| addr.to_string())?)
        }

        /// Get the number of connections (≈sessions) that are currently open.
        fn open_connections(&self) -> i64 {
            self.0.open_connections() as _
        }

        /// Get QUIC activity stats.
        ///
        /// - `accepted_handshakes`
        /// - `outgoing_handshakes`
        /// - `refused_handshakes`
        /// - `ignored_handshakes`
        fn stats(&self) -> HashMap<&'static str, u64> {
            let stats = self.0.stats();
            let mut dict = HashMap::with_capacity(4);
            dict.insert("accepted_handshakes", stats.accepted_handshakes);
            dict.insert("outgoing_handshakes", stats.outgoing_handshakes);
            dict.insert("refused_handshakes", stats.refused_handshakes);
            dict.insert("ignored_handshakes", stats.ignored_handshakes);
            dict
        }

        /// Wait for all sessions on the endpoint to be cleanly shut down.
        ///
        /// Waiting for this condition before exiting ensures that a good-faith effort is made to
        /// notify peers of recent session closes, whereas exiting immediately could force them to
        /// wait out the idle timeout period.
        ///
        /// Does not proactively close existing sessions or cause incoming sessions to be rejected.
        /// Consider calling `session.close()` if that is desired.
        fn wait_idle(&self, py: Python) -> BResult<()> {
            let this = self.0.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                this.wait_idle().await;
                Ok(())
            })?;
            Ok(())
        }

        /// Connect to a peer.
        fn connect<'py>(&self, py: Python<'py>, addrs: String) -> BResult<Bound<'py, PyAny>> {
            let this = self.0.clone();
            Ok(pyo3_async_runtimes::tokio::future_into_py(
                py,
                async move {
                    let sesh = this.connect(addrs).await.map_err(BError::from)?;
                    Ok(Session(sesh))
                },
            )?)
        }

        /// Accept an incoming session.
        ///
        /// Using this is a bit un-Python-y. Conceptually, it's an async iterator which may throw
        /// at each call, and should be stopped once the function successfully returns `none`.
        fn accept<'py>(&self, py: Python<'py>) -> BResult<Bound<'py, PyAny>> {
            let this = self.0.clone();
            Ok(pyo3_async_runtimes::tokio::future_into_py(
                py,
                async move {
                    Ok(this
                        .accept()
                        .await
                        .transpose()
                        .map_err(BError::from)?
                        .map(Session))
                },
            )?)
        }
    }

    /// A Session, able to accept/create streams and send/recv datagrams.
    ///
    /// If all references to a session have been dropped, then the session will be automatically
    /// closed with a `code` of 0 and an empty reason. You can also close the session explicitly by
    /// calling `session.close()`.
    ///
    /// Closing the session immediately sends a `CONNECTION_CLOSE` frame and then abandons efforts
    /// to deliver data to the peer. Upon receiving a `CONNECTION_CLOSE` frame, the peer may drop
    /// any stream data not yet delivered to the application. `session.close()` describes in more
    /// detail how to gracefully close a session without losing application data.
    #[pyclass]
    #[derive(Debug, Clone)]
    pub struct Session(mushi::Session);

    #[pymethods]
    impl Session {
        /// The public key of the remote peer.
        ///
        /// This may be unavailable if `require_client_auth` was set to `false` in the `Allower`.
        fn peer_key(&self) -> Option<Vec<u8>> {
            self.0.peer_key().map(|k| k.to_vec())
        }

        /// The maximum size of a datagram that can be sent.
        fn max_datagram_size<'py>(&self, py: Python<'py>) -> BResult<Bound<'py, PyAny>> {
            let this = self.0.clone();
            Ok(pyo3_async_runtimes::tokio::future_into_py(
                py,
                async move { Ok(this.max_datagram_size().await) },
            )?)
        }

        /// Wait until the peer creates a new unidirectional stream.
        ///
        /// Will error if the session has been closed.
        fn accept_uni<'py>(&self, py: Python<'py>) -> BResult<Bound<'py, PyAny>> {
            let this = self.0.clone();
            Ok(pyo3_async_runtimes::tokio::future_into_py(
                py,
                async move {
                    Ok(this
                        .accept_uni()
                        .await
                        .map(RecvStream::new)
                        .map_err(BError::from)?)
                },
            )?)
        }

        /// Wait until the peer creates a new bidirectional stream.
        ///
        /// Will error if the session has been closed.
        fn accept_bi<'py>(&self, py: Python<'py>) -> BResult<Bound<'py, PyAny>> {
            let this = self.0.clone();
            Ok(pyo3_async_runtimes::tokio::future_into_py(
                py,
                async move {
                    Ok(this
                        .accept_bi()
                        .await
                        .map(|(s, r)| BidiStream {
                            send: Some(SendStream::new(s)),
                            recv: Some(RecvStream::new(r)),
                        })
                        .map_err(BError::from)?)
                },
            )?)
        }

        /// Open a new bidirectional stream.
        ///
        /// May wait when there are too many concurrent streams.
        fn open_bi<'py>(&self, py: Python<'py>) -> BResult<Bound<'py, PyAny>> {
            let this = self.0.clone();
            Ok(pyo3_async_runtimes::tokio::future_into_py(
                py,
                async move {
                    Ok(this
                        .open_bi()
                        .await
                        .map(|(s, r)| BidiStream {
                            send: Some(SendStream::new(s)),
                            recv: Some(RecvStream::new(r)),
                        })
                        .map_err(BError::from)?)
                },
            )?)
        }

        /// Open a new unidirectional stream.
        ///
        /// May wait when there are too many concurrent streams.
        fn open_uni<'py>(&self, py: Python<'py>) -> BResult<Bound<'py, PyAny>> {
            let this = self.0.clone();
            Ok(pyo3_async_runtimes::tokio::future_into_py(
                py,
                async move {
                    Ok(this
                        .open_uni()
                        .await
                        .map(SendStream::new)
                        .map_err(BError::from)?)
                },
            )?)
        }

        /// Send an unreliable datagram over the network.
        ///
        /// QUIC datagrams may be dropped for any reason, including (non-exhaustive):
        ///
        /// - Network congestion
        /// - Random packet loss
        /// - Payload is larger than `max_datagram_size()`
        /// - Peer is not receiving datagrams
        /// - Peer has too many outstanding datagrams
        fn send_datagram(&self, payload: Vec<u8>) -> BResult<()> {
            Ok(self.0.send_datagram(payload.into())?)
        }

        /// Receive a datagram over the network.
        fn recv_datagrams<'py>(&self, py: Python<'py>) -> BResult<Bound<'py, PyAny>> {
            let this = self.0.clone();
            Ok(pyo3_async_runtimes::tokio::future_into_py(
                py,
                async move {
                    Ok(this
                        .recv_datagram()
                        .await
                        .map(|b| b.to_vec())
                        .map_err(BError::from)?)
                },
            )?)
        }

        /// Close the session immediately.
        ///
        /// Pending operations will fail immediately with a `LocallyClosed` error. No more data is
        /// sent to the peer beyond a `CONNECTION_CLOSE` frame, and the peer may drop buffered data
        /// upon receiving the `CONNECTION_CLOSE` frame.
        ///
        /// `code` and `reason` are not interpreted, and are provided directly to the peer.
        ///
        /// `reason` will be truncated to fit in a single packet with overhead; to improve odds
        /// that it is preserved in full, it should be kept under 1KiB.
        ///
        /// # Gracefully closing a session
        ///
        /// Only the peer last receiving application data can be certain that all data is
        /// delivered. The only reliable action it can then take is to close the session,
        /// potentially with a custom error code. The delivery of the final `CONNECTION_CLOSE`
        /// frame is very likely if both endpoints stay online long enough, and
        /// `endpoint.wait_idle()` can be used to provide sufficient time. Otherwise, the remote
        /// peer will time out the session after 30 seconds.
        ///
        /// The sending side can not guarantee all stream data is delivered to the remote
        /// application.
        ///
        /// It only knows the data is delivered to the QUIC stack of the remote endpoint. Once the
        /// local side sends a `CONNECTION_CLOSE` frame, the remote endpoint may drop any data it
        /// received but is as yet undelivered to the application, including data that was
        /// acknowledged as received to the local endpoint.
        fn close(&self, code: i32, reason: String) {
            self.0.close(code as _, &reason)
        }

        /// Wait until the connection is closed.
        ///
        /// Returns `null` if the connection was closed locally, and a string if the connection was
        /// closed by a peer (e.g. with `close()`). Throws for other unexpected close reasons.
        fn closed<'py>(&self, py: Python<'py>) -> BResult<Bound<'py, PyAny>> {
            let this = self.0.clone();
            Ok(pyo3_async_runtimes::tokio::future_into_py(
                py,
                async move {
                    Ok(this
                        .closed()
                        .await
                        .map(|r| r.map(|reason| reason.to_string()))
                        .map_err(BError::from)?)
                },
            )?)
        }
    }

    /// A handle to a QUIC receive stream.
    ///
    /// It's important to never call methods on this object concurrently, ie not to do two reads,
    /// or to call `stop()` while reading the stream in an overlapping async context. The stream
    /// has an internal mutex (lock), and overlapping accesses will introduce undesirable
    /// contention.
    #[pyclass]
    #[derive(Debug, Clone)]
    pub struct RecvStream(Arc<Mutex<mushi::RecvStream>>);

    impl RecvStream {
        // **not** a python constructor
        fn new(s: mushi::RecvStream) -> Self {
            Self(Arc::new(Mutex::new(s)))
        }
    }

    #[pymethods]
    impl RecvStream {
        /// Read the next chunk of data with the provided maximum size.
        ///
        /// Returns `null` if there's nothing more to read (the stream is closed).
        fn read<'py>(&self, py: Python<'py>, max: usize) -> BResult<Bound<'py, PyAny>> {
            let this = self.0.clone();
            Ok(pyo3_async_runtimes::tokio::future_into_py(
                py,
                async move {
                    Ok(this
                        .lock()
                        .await
                        .read(max)
                        .await
                        .map(|b| b.map(|bytes| bytes.to_vec()))
                        .map_err(BError::from)?)
                },
            )?)
        }

        /// Send a `STOP_SENDING` QUIC code.
        fn stop(&self, py: Python, code: u32) -> BResult<()> {
            let this = self.0.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                Ok(this.lock().await.stop(code))
            })?;
            Ok(())
        }
    }

    /// A handle to a QUIC send stream.
    ///
    /// It's important to never call methods on this object concurrently, ie not to do two writes,
    /// or to call `setPriority()` while writing to the stream in an overlapping async context. The
    /// stream has an internal mutex (lock), and overlapping accesses will introduce undesirable
    /// contention.
    #[pyclass]
    #[derive(Debug, Clone)]
    pub struct SendStream(Arc<Mutex<mushi::SendStream>>);

    impl SendStream {
        // **not** a python constructor
        fn new(s: mushi::SendStream) -> Self {
            Self(Arc::new(Mutex::new(s)))
        }
    }

    #[pymethods]
    impl SendStream {
        /// Write the payload to the stream.
        fn write(&self, py: Python, payload: Vec<u8>) -> BResult<()> {
            let this = self.0.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                Ok(this
                    .lock()
                    .await
                    .write(&payload)
                    .await
                    .map_err(BError::from)?)
            })?;
            Ok(())
        }

        /// Set the stream’s priority.
        ///
        /// Streams with lower values will be sent first, but are not guaranteed to arrive first.
        fn set_priority(&self, py: Python, priority: i32) -> BResult<()> {
            let this = self.0.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                Ok(this.lock().await.set_priority(priority))
            })?;
            Ok(())
        }

        /// Send an immediate reset code, closing the stream.
        fn reset(&self, py: Python, code: u32) -> BResult<()> {
            let this = self.0.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                Ok(this.lock().await.reset(code))
            })?;
            Ok(())
        }
    }

    /// Return value of `accept_bi()` and `open_bi()`.
    ///
    /// This can be used to obtain (once) the recv and send streams.
    #[pyclass]
    #[derive(Debug)]
    pub struct BidiStream {
        recv: Option<RecvStream>,
        send: Option<SendStream>,
    }

    #[pymethods]
    impl BidiStream {
        /// Obtain the recv stream.
        ///
        /// May only be called once. After that, it will return none.
        fn take_recv(&mut self) -> Option<RecvStream> {
            self.recv.take()
        }

        /// Obtain the send stream.
        ///
        /// May only be called once. After that, it will return none.
        fn take_send(&mut self) -> Option<SendStream> {
            self.send.take()
        }
    }
}

mod error {
    use pyo3::{DowncastError, PyErr};

    pub(crate) type BResult<T> = Result<T, BError>;

    #[derive(Debug, thiserror::Error)]
    pub(crate) enum BError {
        #[error("python: {0}")]
        Python(#[from] PyErr),

        #[error("key: {0}")]
        RcGen(#[from] mushi::rcgen::Error),

        #[error("key: unsupported type {0:?}")]
        UnsupportedKeyType(String),

        #[error("endpoint: unknown congestion control {0:?}")]
        UnknownCongestionControl(String),

        #[error("mushi: {0}")]
        Mushi(#[from] mushi::Error),

        #[error("argument is not a callable: {0}")]
        NotCallable(&'static str),
    }

    impl From<BError> for PyErr {
        fn from(err: BError) -> Self {
            use pyo3::exceptions::*;
            match err {
                BError::Python(e) => e,
                e @ BError::NotCallable(_) => PyTypeError::new_err(e.to_string()),
                e => PyValueError::new_err(e.to_string()),
            }
        }
    }

    impl From<DowncastError<'_, '_>> for BError {
        fn from(err: DowncastError<'_, '_>) -> Self {
            Self::Python(err.into())
        }
    }
}
