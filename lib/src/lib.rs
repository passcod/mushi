//! Mushi is point-to-point QUIC networking with application-defined mutual authentication.
//!
//! It takes inspiration from [Iroh](https://iroh.computer).
//!
//! In Mushi, peers are identified by a persistent key pair (ECDSA or ED25519). Connecting to peers
//! is done by DNS or IP addresses (it doesn't have peer discovery or NAT traversal). Trust is
//! decided based on the peers' public key (which may be considered an opaque binary blob).
//! Endpoints handle both outgoing (client) and incoming (server) function: typically, a single
//! [Endpoint] is started per application. Connecting to (or accepting an incoming connection from)
//! another peer creates a [Link], which is a single bidirectional stream. Multiple Links between
//! a unique peer pair are transparently multiplexed on a single QUIC connection whenever possible.
//!
//! All communications are secured with TLS 1.3, with RSA suites explicitly disabled. Endpoints
//! have a key pair (which may be generated on startup), and each connection uses a unique
//! just-in-time short-lived certificate (valid for 2 minutes — TODO: validity not checked now).
//!
//! This provides authentication: peers are guaranteed to have control over their own key pair, and
//! it's unfeasible for an attacker in possession of a public key to obtain the associate private
//! key to be able to successfully spoof an endpoint.
//!
//! However, it does not provide authorisation. Mushi applications must decide whether key trust is
//! sufficient, or if they should have an additional auth layer; Mushi itself does not facilitate
//! or prefer any specific scheme.
//!
//! Mushi does not at present implement ECH (Encrypted Client Hello). This may be added in the
//! future; it would require providing the public key of the remote peer upfront.
//!
//! # Example TODO: fixme
//!
//! ```ignore
//! use mushi::{AllowAllConnections, Endpoint, EndpointKey, Session};
//!
//! #[tokio::main]
//! async fn main() {
//!     mushi::install_crypto_provider();
//!
//!     let key = EndpointKey::generate().unwrap();
//!     let policy = Arc::new(AllowAllConnections);
//!     let end = Endpoint::new("[::]:0", key, policy, None).unwrap();
//!
//!     let mut session = end.connect("remotepeer.example.com:1310").await.unwrap();
//!     session.send_datagram("Hello world".into()).unwrap();
//!
//!     let (mut s, mut r) = session.open_bi().await.unwrap();
//!     s.write(b"How are you today?").await.unwrap();
//!     let response = r.read(1024).await.unwrap();
//!     println!("peer said: {response:x?}");
//! }
//! ```
#![warn(missing_docs)]

pub use crate::{
    endpoint::*, error::*, key::*, link::*, provider::install_crypto_provider, session::*,
};
pub use rcgen;
pub use rustls::{CertificateError, pki_types::SubjectPublicKeyInfoDer};
pub use url::Url;
pub use web_transport_quinn::{self as web_transport, quinn, quinn::rustls};

mod endpoint;
mod error;
mod key;
mod link;
mod provider;
mod session;
