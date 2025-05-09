import test from "ava";

import { EndpointKey } from "../index.js";

test("generate and round trip a key", (t) => {
  const pem1 = EndpointKey.generate().privateKeyPem;
  const pem2 = new EndpointKey(pem1).privateKeyPem;
  t.is(pem1, pem2);
});

test("validity accessors", (t) => {
  const k = EndpointKey.generate();
  t.is(k.validity, 120);
  k.validity = 300;
  t.is(k.validity, 300);
});

test("key types", (t) => {
  const k1 = EndpointKey.generateFor("ed25519");
  t.is(k1.publicKeyPem.replaceAll(/\s+/g, "").length, 106);
  const k2 = EndpointKey.generateFor("ecdsa256");
  t.is(k2.publicKeyPem.replaceAll(/\s+/g, "").length, 170);
  const k3 = EndpointKey.generateFor("ecdsa384");
  t.is(k3.publicKeyPem.replaceAll(/\s+/g, "").length, 206);
});

test("cert types", (t) => {
  const k1 = EndpointKey.generateFor("ed25519");
  t.assert(k1.makeCertificate().length > 600);
  const k2 = EndpointKey.generateFor("ecdsa256");
  t.assert(k2.makeCertificate().length > 700);
  const k3 = EndpointKey.generateFor("ecdsa384");
  t.assert(k3.makeCertificate().length > 800);
});

test("thousand keys", (t) => {
  let n = 0;
  for (let i = 0; i < 1000; i += 1) {
    const k = EndpointKey.generate();
    t.truthy(k);
    t.truthy(k.publicKeyPem);
    t.assert(typeof k.publicKeyPem === "string");
    n += k.publicKeyPem.length;
  }
  t.assert(n > 0);
});
