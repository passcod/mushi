# Mushi 🫖🍵

_What if we could mush other protocols into Web Transport?_

## What is this?

**[WebTransport]** is this really fun Web technology that lets you use QUIC almost
directly in the browser. QUIC is what HTTP/3 is based on, and it's a new-ish reliable
protocol layered over UDP and TLS. It's like TCP version 2. QUIC (and WebTransport,
thereafter "WT") gives you a secure connection and within that, either endpoint can
create arbitrary amounts of uni-directional (uni) and bi-directional (bidi) streams, and
can send unreliable datagrams. Streams are really cheap, to the point it's not uncommon
to send a single message down a new uni stream, and then discard it. In my opinion, QUIC
(and WT) completely changes the economy of connectivity for web and network applications.

QUIC, at a security level, is "just" TLS, so you can use all kinds of existing topologies
to deal with this. You can use publicly trusted web certificates (thereafter, "WebPKI"),
you can use self-signed certificates, or private certificate authorities, or even do the
new-fangled SPKI-based [RFC 7250] scheme. You can do mutual TLS, always or on option.

However, on the Web, you're restricted to HTTPS over WebPKI, with a narrow localhost
exemption. Every new and powerful Web technology has to be served from a Secure Origin
(which is whatever your browser trusts, ie WebPKI) or from localhost, and you cannot
downgrade inside the page served. For example, you can't do plain HTTP from an HTTPS
page (unless it's to localhost). If you're on the Web, you need WebPKI everywhere.

**Except for WebTransport**. WT has a completely unique API for the modern Web:
[`serverCertificateHashes`](https://developer.mozilla.org/en-US/docs/Web/API/WebTransport/WebTransport#servercertificatehashes).
It is explicitly set out as an alternative to using WebPKI, and is supported by all
current major browsers in Secure Origins. You still need the website to be served from
HTTPS (or localhost). But from there, you can do _WebPKI-less_ secure connections to
anywhere you want: local, LAN, arbitrary devices on the network. All you need is an
address and a valid hash.

There are two obstacles to this:
- to get an address and a valid hash, you need a backchannel of some kind. Hashes are
  valid for no longer than two weeks, and you need some way for clients to obtain them
  and probably also to rotate them.
- there's very little support in the server world.

Mushi exists to solve the second problem. It's a library that serves WT and facilitates
server cert hash creation and rotation. You provide the backchannel and you obtain a WT
server API.

But the second problem then extends: fine, you have WT. But no framework supports WT.
You want to have Web access to your HTTP API, not to a new greenfield API. At a stretch
you might have a WebSocket API. Maybe you want gRPC. Or even just plain TCP or UDP.

Mushi thus provides **adapters** that _mush_ other protocols into WT.

You can take your existing HTTP server, re-expose it over WT, and on the Web side, you
can use native `fetch()` to talk to it. The client part is tiny and not a WASM blob.

[WebTransport]: https://developer.mozilla.org/en-US/docs/Web/API/WebTransport_API
[RFC 7250]: https://www.rfc-editor.org/info/rfc7250/

## How do I use this?

Mushi is [a Rust crate][lib-rust] ([docs][docs-rust]), with some foreign interfaces for
convenience:

- [Node.js][lib-node] ([docs][docs-node])
- [a CLI tool][cli] ([docs][docs-cli])

Other FFI is possible; enquire within.

[lib-rust]: https://lib.rs/crate/mushi
[docs-rust]: https://docs.rs/mushi
[lib-node]: https://www.npmjs.com/package/mushi
[docs-node]: https://passcod.github.io/mushi/js/
[cli]: https://lib.rs/crate/mushi-cli
[docs-cli]: https://github.com/passcod/mushi/blob/main/cli/README.md

🧋
