# Mushi 🫖🍵

_WebTransport for browsers, without PKI._

This is the Node.js binding: it runs the **server** side, which browsers reach by pinning the
certificate hash instead of validating a chain.

```js
import { Identity, Server } from "mushi";

const cert = Identity.generate().issue();
console.log("publish this hash:", cert.hashSri); // sha256-47DEQpj8...

const server = new Server("[::]:4433", cert);
while (true) {
  const request = await server.accept();
  if (!request) break;

  if (request.path === "/my-app") {
    const session = await request.ok();
    // streams and datagrams
  } else {
    await request.reject(404);
  }
}
```

Certificates last under two weeks, so rotate them — publish before you serve:

```js
const rotation = server.rotation;

if (rotation.current.needsRenewal(lead)) {
  rotation.stage(identity.issue());
  await publish(rotation.publishedSri); // only proceed once this is confirmed
  rotation.promote();
}

rotation.retirePreviousIfDue(propagation);
```

Persist the certificate with `toPem()`/`keyPem` and reload it with `Certificate.fromPem()`: the
hash covers the certificate, not the key, so a device that reissues on boot is unreachable until it
republishes.

See <https://github.com/passcod/mushi> for the whole story, including what the browser requires of
the certificate and why there's no client authentication.

🧋
