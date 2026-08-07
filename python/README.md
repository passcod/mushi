# pymushi — parked

These bindings target Mushi's **pre-pivot API**, when Mushi was a symmetric peer-to-peer transport
with mutual TLS authentication. That model was dropped: browsers cannot present client
certificates, and for native peer-to-peer you're better served by plain [quinn] than by
WebTransport on top of it.

As a result this crate **does not build**, and is excluded from the workspace and from CI.

Reviving it is not difficult — the surface to mirror is `nodejs/src/lib.rs`, which wraps the same
core:

- `EndpointKey` → `Identity`, plus a new `Certificate` exposing the hash browsers pin
- `Allower` → deleted; authorise on `Request.path` and `Request.origin` instead
- `Endpoint` → `Server`, with `accept()` yielding a `Request` to accept or reject

It was never published to PyPI, so nothing downstream breaks in the meantime.

[quinn]: https://docs.rs/quinn
