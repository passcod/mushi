# Mushi 🫖🍵

_WebTransport for browsers, without PKI._

> [!WARNING]
> Mushi is being rebuilt around a new purpose and is **not ready for use**. See
> [Status](#status) for what works today.

## What is this?

A browser can't talk to a device that has no publicly-trusted certificate. Local addresses can't
get one — no CA will issue for `192.168.1.47` — and mixed-content rules block plain HTTP. The
usual escapes are all miserable: ship a local CA, tunnel everything through the cloud, or play
DNS games to point a real certificate at a private address.

WebTransport has a sanctioned way out. Its [`serverCertificateHashes`] option lets a page name the
SHA-256 of the certificate it expects, and the browser skips chain validation entirely. **Mushi is
the server side of that arrangement.**

The intended shape is a cloud app plus a local device:

1. Your app is served from an origin the browser already trusts, over ordinary HTTPS.
2. That origin tells the page which certificate hashes the device is currently serving.
3. The page connects straight to the device over WebTransport, pinning those hashes.

Nothing needs to be installed in the browser — the native [`WebTransport`] API is enough.

```js
const wt = new WebTransport(`https://${device}:4433/my-app`, {
  serverCertificateHashes: [{ algorithm: "sha-256", value: hashFromYourBackend }],
});
await wt.ready;
```

## What the browser imposes

The certificate rules come from the WebTransport specification, not from Mushi, and they shape the
whole design:

- **ECDSA P-256 only.** RSA is banned outright; Ed25519 isn't permitted either.
- **Under 14 days of validity.** Short life stands in for revocation, so certificates get
  **rotated**, not issued once. Because the browser accepts a *list* of hashes, publishing the
  current and next hash together makes rotation seamless.
- **SHA-256** is the only hash algorithm currently specified.
- **No client certificates.** The browser has no way to present one, at any layer.

That last point is why Mushi no longer does mutual authentication. Authorise at the handshake
instead: the browser can't set request headers and WebTransport doesn't send cookies, so the **URL
path is the only channel it controls** — it carries both protocol selection and whatever token you
authenticate with. The `Origin` header, set by the browser itself, is worth checking too.

Because the browser pins a hash of the whole certificate rather than a key, it doesn't care what's
inside. The scheme is naturally crypto-agile: when browsers accept a new signature algorithm, you
can serve certificates under it and publish both hashes, with no protocol change.

## Using it

```rust
let identity = mushi::Identity::generate()?;
let cert = identity.issue(mushi::DEFAULT_VALIDITY, ["device.local".parse()?])?;

// Publish this via your cloud app, over an origin the browser already trusts.
println!("{}", cert.hash().to_hex());

let server = mushi::Server::builder()
    .with_addr("[::]:4433".parse()?)
    .with_certificate(cert)?;

while let Some(request) = server.accept().await {
    match request.path() {
        "/my-app" => {
            let session = request.ok().await?;
            // streams and datagrams
        }
        _ => request.reject(mushi::StatusCode::NOT_FOUND).await?,
    }
}
```

Mushi is [a Rust crate][lib-rust] ([docs][docs-rust]) with bindings for [Node.js][lib-node]
([docs][docs-node]).

## Status

Rebuilt around the browser use case. Working today:

- Certificate issuance under the browser's constraints, with the hash to pin
- Hot certificate replacement on a running server, for rotation
- Path routing and rejection at the handshake, and subprotocol negotiation where supported
- Streams (uni and bidi, in both directions) and datagrams

Not yet:

- **Scheduled rotation.** `Server::set_certificate` swaps the certificate; deciding *when*, and
  publishing the overlapping hash set, is still yours to write.
- **Verification against a real browser.** The test suite pins hashes exactly as a browser does,
  but no browser has been driven against this yet.
- **Protocols on top.** The plan is to tunnel ordinary web protocols over WebTransport so a
  PKI-less device can look like a normal origin: `mushi-http` (a service worker making real
  `fetch` work, which also covers subresources and SSE), then `mushi-ws`.
- **Python bindings**, which are [parked](./python/README.md) on the pre-pivot API.

Prior to this, Mushi was a symmetric peer-to-peer transport with mutual TLS authentication. That
was dropped: browsers can't do it, and for native peer-to-peer you're better off with plain
[quinn] than with WebTransport layered on top.

[`serverCertificateHashes`]: https://developer.mozilla.org/en-US/docs/Web/API/WebTransport/WebTransport#servercertificatehashes
[`WebTransport`]: https://developer.mozilla.org/en-US/docs/Web/API/WebTransport
[lib-rust]: https://lib.rs/crate/mushi
[docs-rust]: https://docs.rs/mushi
[lib-node]: https://www.npmjs.com/package/mushi
[docs-node]: https://passcod.github.io/mushi/js/
[quinn]: https://docs.rs/quinn

🧋
