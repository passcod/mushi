import test from "ava";

import { Identity } from "../index.js";

test("generates and round-trips through PEM", (t) => {
  const id = Identity.generate();
  t.true(id.privateKeyPem.includes("PRIVATE KEY"));
  t.true(id.publicKeyPem.includes("PUBLIC KEY"));

  const loaded = new Identity(id.privateKeyPem);
  t.is(loaded.publicKeyPem, id.publicKeyPem);
});

test("rejects a key browsers can't use", (t) => {
  t.throws(() => new Identity("not a pem"));
});

test("issues a certificate browsers would accept", (t) => {
  const cert = Identity.generate().issue();

  t.is(cert.hashAlgorithm, "sha-256");
  t.is(cert.hash.length, 32);
  t.is(cert.hashHex.length, 64);
  t.is(cert.hashHex, cert.hash.toString("hex"));
  t.true(cert.isBrowserValid);

  // Under 14 days, and backdated so a trailing clock still works.
  t.true(cert.notAfter - cert.notBefore < 14 * 24 * 60 * 60 * 1000);
  t.true(cert.notBefore < Date.now());
});

test("refuses validity browsers would reject", (t) => {
  const id = Identity.generate();
  const fortnight = 14 * 24 * 60 * 60;

  t.throws(() => id.issue(fortnight));
  t.throws(() => id.issue(fortnight + 1));
  t.throws(() => id.issue(0));
  t.notThrows(() => id.issue(fortnight - 1));
});

test("rotating changes the hash even on the same key", (t) => {
  const id = Identity.generate();
  t.not(id.issue().hashHex, id.issue().hashHex);
});
