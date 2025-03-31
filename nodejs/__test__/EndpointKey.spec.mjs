import test from "ava";

import { EndpointKey } from "../index.js";

test("generate and round trip a key", (t) => {
  const pem1 = EndpointKey.generate().privateKeyPem();
  const pem2 = new EndpointKey(pem1).privateKeyPem();
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
  t.is(k1.publicKeyPem.length, 113);
  const k2 = EndpointKey.generateFor("ecdsa256");
  t.is(k2.publicKeyPem.length, 178);
  const k3 = EndpointKey.generateFor("ecdsa384");
  t.is(k3.publicKeyPem.length, 215);
});

test("cert types", (t) => {
  const k1 = EndpointKey.generateFor("ed25519");
  t.assert(k1.makeCertificate().length > 600);
  const k2 = EndpointKey.generateFor("ecdsa256");
  t.assert(k2.makeCertificate().length > 700);
  const k3 = EndpointKey.generateFor("ecdsa384");
  t.assert(k3.makeCertificate().length > 800);
});
