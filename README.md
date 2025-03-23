# Mushi

_WebTransport with client auth._

## API

Mushi simply exposes [WebTransport](https://developer.mozilla.org/en-US/docs/Web/API/WebTransport).

## What?

**[Iroh](https://iroh.computer)** is peer-to-peer QUIC connections with peer-to-peer
authentication based on ED25519 keys. **Mushi** is client-server QUIC connections with
peer-to-peer authentication based on X.509 keys.

If you're not familiar, Iroh is this really neat project that offers the same kind of
"it just works" networking as [Tailscale](https://tailscale.com), but embedded directly
into applications, like you'd have TCP or HTTP. Iroh performs all the NAT traversal,
hole-punching, port negotiation, discovery of peers, etc... and you get a super-simple
`Endpoint` structure that you can talk to other peers with. The cryptography of Iroh is
based on mTLS: each peer has an ED25519 keypair, and uses it both as a certificate and
as a node identity. There's no PKI: an incoming connection presents its ED25519 public
key, the TLS handshake makes sure that it's authentic, and it's up to the application
whether it trusts that key (and establishes the connection) or not.

Mushi came about when wanting something similar to Iroh, but in a context where the
peer-to-peer bits were unnecessary (and in fact counter-productive), but where web PKI
was inappropriate, and an application-defined trust model with mutually-authenticated
peers was more desirable. Additionally, with discovery and other details unused, it
became easier to be flexible on the cryptography suite: Mushi works with anything that
TLS 1.3 does, such as ECDSA, rather than being restricted to ED25519.

In the end, Mushi is:

- QUIC
- with short-lived self-signed certificates on both client and server sides
- from persistent (long-lived) keypairs
- wrapped in the WebTransport API

On connection establishment, an Endpoint receives the DER-encoded Public Key Information
block of the other side, and can use that as an opaque identity blob for the remote peer.
That structure contains both the public key data and an algorithm specifier, which lets
peers choose from ECDSA or ED25519 as is more convenient for them. (RSA is not allowed.)

## How do I use this?

Mushi is a Rust crate, with some foreign interfaces for convenience:

- a Node.js module
- a Python wheel
- a CLI tool
