# Mushi 🫖🍵

_WebTransport with mutual authentication._

## What is this?

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
key, the TLS handshake makes sure it's authentic, and it's up to the application whether
it trusts that key (and establishes the connection) or not.

Mushi came about when wanting something similar to Iroh, but in a context where the
peer-to-peer bits were unnecessary (and in fact counter-productive), and where web PKI
was inappropriate, yet an application-defined trust model with mutually-authenticated
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
applications choose from ECDSA or ED25519 as is more convenient. (RSA is not allowed.)

## How do I use this?

Mushi is [a Rust crate][lib-rust] ([docs][docs-rust]), with some foreign interfaces for
convenience:

- [a Node.js module][lib-node] ([docs][docs-node])
- [a Python wheel][lib-python] ([docs][docs-python])
- [a CLI tool][cli] ([docs][docs-cli])

Mushi is also nothing special: as long as you have TLS-level control for your WebTransport
implementation, you can play along. Require client certificates, don't validate against web
PKI, match public keys instead, and prefer issuing short-lived certificates on the fly.

[lib-rust]: https://lib.rs/crate/mushi
[docs-rust]: https://docs.rs/mushi
[lib-node]: https://www.npmjs.com/package/mushi
[docs-node]: https://passcod.github.io/mushi/js/
[lib-python]: https://pypi.org/mushi-todo
[docs-python]: https://todo.example.com
[cli]: https://lib.rs/crate/mushi-cli
[docs-cli]: https://github.com/passcod/mushi/blob/main/cli/README.md

🧋
