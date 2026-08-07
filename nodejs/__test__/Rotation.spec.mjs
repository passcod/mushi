import test from "ava";

import { Certificate, Identity, Server } from "../index.js";

const BIND = "127.0.0.1:0";

function cert() {
  return Identity.generate().issue();
}

test("a certificate survives a restart", (t) => {
  const original = cert();
  const reloaded = Certificate.fromPem(original.toPem(), original.keyPem);

  // The whole point: same certificate, so the already-published hash still matches.
  t.is(reloaded.hashSri, original.hashSri);
  t.true(reloaded.isBrowserValid);
  // Certificates store whole seconds.
  t.true(Math.abs(reloaded.notAfter - original.notAfter) < 1000);
});

test("reloading rejects malformed input", (t) => {
  const c = cert();
  t.throws(() => Certificate.fromPem("not a pem", c.keyPem));
  t.throws(() => Certificate.fromPem(c.toPem(), "not a pem"));
});

test("renewal is due a lead time before expiry", (t) => {
  const c = Identity.generate().issue(3600);

  t.is(c.renewAt(600), c.notAfter - 600 * 1000);
  t.false(c.needsRenewal(600));
  // A lead longer than the remaining life means renewal is already overdue.
  t.true(c.needsRenewal(7200));
});

test("staging publishes without serving", (t) => {
  const current = cert();
  const server = new Server(BIND, current);
  try {
    const rotation = server.rotation;
    t.is(rotation.publishedSri, current.hashSri);

    const next = cert();
    rotation.stage(next);

    // Published, so browsers can learn it...
    t.true(rotation.publishedSri.includes(next.hashSri));
    // ...but not served, which is the entire ordering guarantee.
    t.is(rotation.current.hashSri, current.hashSri);
    t.is(rotation.staged.hashSri, next.hashSri);
    t.is(server.certificate.hashSri, current.hashSri);
  } finally {
    server.close(0, "done");
  }
});

test("promoting serves the staged certificate and keeps the old one published", (t) => {
  const current = cert();
  const next = cert();
  const server = new Server(BIND, current);
  try {
    const rotation = server.rotation;
    rotation.stage(next);
    const promoted = rotation.promote();

    t.is(promoted.hashSri, next.hashSri);
    t.is(server.certificate.hashSri, next.hashSri);
    t.is(rotation.staged, null);

    // The displaced one stays published so a stale snapshot still connects.
    t.is(rotation.previous.hashSri, current.hashSri);
    t.true(rotation.publishedSri.includes(current.hashSri));
    t.true(rotation.publishedSri.includes(next.hashSri));
  } finally {
    server.close(0, "done");
  }
});

test("promoting with nothing staged throws", (t) => {
  const server = new Server(BIND, cert());
  try {
    t.throws(() => server.rotation.promote());
  } finally {
    server.close(0, "done");
  }
});

test("retiring is manual and gated on propagation", (t) => {
  const current = cert();
  const server = new Server(BIND, current);
  try {
    const rotation = server.rotation;

    // Nothing to retire before the first promotion.
    t.is(rotation.retirePreviousAt(3600), null);
    t.is(rotation.retirePrevious(), null);

    rotation.stage(cert());
    rotation.promote();

    t.true(rotation.retirePreviousAt(3600) > Date.now());

    // Not due yet, so the helper leaves it alone and the hash stays published.
    t.is(rotation.retirePreviousIfDue(3600), null);
    t.true(rotation.publishedSri.includes(current.hashSri));

    // Due, so it goes.
    t.is(rotation.retirePreviousIfDue(0).hashSri, current.hashSri);
    t.false(rotation.publishedSri.includes(current.hashSri));
    t.is(rotation.previous, null);
  } finally {
    server.close(0, "done");
  }
});

test("an expired certificate is refused rather than served", (t) => {
  const server = new Server(BIND, cert());
  try {
    // Issuance backdates five minutes, so this one is already past its notAfter.
    const expired = Identity.generate().issue(60);
    t.throws(() => server.rotation.stage(expired));
    t.throws(() => server.rotation.replace(expired));
  } finally {
    server.close(0, "done");
  }
});

test("waiters see changes to the published set", async (t) => {
  const server = new Server(BIND, cert());
  try {
    const rotation = server.rotation;
    const next = cert();

    const change = rotation.changed();
    rotation.stage(next);

    t.true((await change).includes(next.hashSri));
  } finally {
    server.close(0, "done");
  }
});
