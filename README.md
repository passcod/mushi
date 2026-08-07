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
  serverCertificateHashes: webTransportHashes(sriFromYourBackend),
});
await wt.ready;
```

## Publishing hashes

Hashes are published in [Subresource Integrity][sri] syntax — `sha256-47DEQpj8...`, several joined
by spaces. That's a deliberate borrow: SRI means *"any of these digests matching is acceptable"*,
which is exactly what `serverCertificateHashes` does with a list, and exactly what a rotation
overlap needs. So the whole publishable set is one string, with no schema to agree on or version.

The browser wants it as a list of objects, which is four lines. Note that SRI and WebTransport
spell the algorithm differently — `sha256` in the token, `sha-256` in the dictionary:

```js
function webTransportHashes(sri) {
  return sri.trim().split(/\s+/).map((token) => {
    const at = token.indexOf("-");
    return {
      algorithm: token.slice(0, at).replace(/^sha/, "sha-"),
      value: Uint8Array.from(atob(token.slice(at + 1)), (c) => c.charCodeAt(0)),
    };
  });
}
```

## Rotating

Certificates last under two weeks, so rotation isn't optional. The catch is ordering: a server
serves exactly one certificate, and nothing in the handshake says which hash the browser pinned, so
it can't choose per-connection. The overlap therefore lives entirely in *publication* — both hashes
must be in what your backend serves **before** the served certificate changes underneath it.

> A certificate must be published, and that publication must have propagated, before it is served.

[`Rotation`][docs-rust] has three slots to make that hard to get wrong. `stage` makes a certificate
publishable without serving it; `promote` starts serving it once you know the hash is out there.
The one it displaces stays published as `previous`, so a rollback or a stale snapshot still
connects, until you `retire_previous`.

```rust
let rotation = server.rotation();

if rotation.current().needs_renewal(lead) {
    rotation.stage(identity.issue(mushi::DEFAULT_VALIDITY)?)?;
    publish(rotation.published_sri()).await?;  // only proceed once this is confirmed
    rotation.promote()?;
}

// Once the old hash has had time to reach every browser.
rotation.retire_previous_if_due(propagation);
```

Nothing runs on a timer. Mushi can't see your backchannel, so it can't know whether a publication
landed, and a schedule that assumed it did would be guessing — `retire_previous_at` and
`needs_renewal` compute deadlines for you to act on. `rotation.watch()` pushes the published set on
every change if you'd rather drive publication reactively than poll.

**Persist the certificate**, not just the identity. The hash covers the certificate, not the key,
so a device that reissues on boot comes back with a hash nobody has published — unreachable until
it republishes and that propagates, which it can't even do if the backchannel is down.
`Certificate::to_pem` and `key_pem` store it; `Certificate::from_pem` reloads it. That is also how
to adopt a certificate issued elsewhere, if your backend mints them and provisions them down.

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
let cert = identity.issue(mushi::DEFAULT_VALIDITY)?;

// Publish this via your cloud app, over an origin the browser already trusts.
println!("{}", cert.hash()); // sha256-47DEQpj8...

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
- Rotation with an overlapping published set, and persistence across restarts
- Path routing and rejection at the handshake, and subprotocol negotiation where supported
- Streams (uni and bidi, in both directions) and datagrams

Not yet:

- **The backchannel itself.** Mushi tells you what to publish and when it is safe to change what it
  serves; getting that to your cloud app, and the device's address alongside it, is yours.
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
[sri]: https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
[lib-rust]: https://lib.rs/crate/mushi
[docs-rust]: https://docs.rs/mushi
[lib-node]: https://www.npmjs.com/package/mushi
[docs-node]: https://passcod.github.io/mushi/js/
[quinn]: https://docs.rs/quinn

🧋
