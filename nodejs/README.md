# Mushi 🫖🍵

_WebTransport for browsers, without PKI._

This is the Node.js binding: it runs the **server** side, which browsers reach by pinning the
certificate hash instead of validating a chain.

```js
import { Identity, Server } from "mushi";

const cert = Identity.generate().issue();
console.log("publish this hash:", cert.hashHex);

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

See <https://github.com/passcod/mushi> for the whole story, including what the browser requires of
the certificate and why there's no client authentication.

🧋
