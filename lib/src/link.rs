use std::{net::SocketAddr, num::NonZero, ops::Deref};

use tinyvec::TinyVec;
use web_transport_quinn::quinn::{self, rustls::pki_types::SubjectPublicKeyInfoDer};

use crate::Endpoint;

/// A subprotocol for a Link.
///
/// This is an arbitrary byte string.
/// You'll get slightly better performance if it's 16 bytes or less.
///
/// ```
/// mushi::Subprotocol::from("login/1");
/// mushi::Subprotocol::from(&[12, 34, 56, 78]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Subprotocol(TinyVec<[u8; 16]>);

impl Deref for Subprotocol {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&str> for Subprotocol {
    fn from(s: &str) -> Self {
        Self(TinyVec::from(s.as_bytes()))
    }
}

impl From<&[u8]> for Subprotocol {
    fn from(bytes: &[u8]) -> Self {
        Self(TinyVec::from(bytes))
    }
}

/// A bidirectional stream to a peer.
#[derive(Debug, Clone)]
pub struct Link {
    id: NonZero<u64>,
    endpoint: Endpoint,
    proto: TinyVec<[u8; 16]>,
}
