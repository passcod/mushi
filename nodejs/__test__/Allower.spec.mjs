import test from "ava";

import { EndpointKey, Allower, Endpoint } from "../index.js";

function pemToBuffer(pem) {
  return Buffer.from(
    pem
      .split("\n")
      .filter((line) => !line.includes("---"))
      .join("")
      .replace(/\s+/g, ""),
    "base64",
  );
}

test("keyset", async (t) => {
  t.timeout(100);

  const k1 = EndpointKey.generate();
  const k2 = EndpointKey.generate();
  const k3 = EndpointKey.generate();

  const a = new Allower((key) =>
    [pemToBuffer(k1.publicKeyPem), pemToBuffer(k2.publicKeyPem)].some((k) =>
      k.equals(key),
    ),
  );

  const e1 = new Endpoint("[::1]:0", k1, a);
  const e2 = new Endpoint("[::1]:0", k2, a);
  const e3 = new Endpoint("[::1]:0", k3, a);

  try {
    const [s1, s2] = await Promise.all([e1.connect(e2.localAddr), e2.accept()]);
    const result = await Promise.all([
      e1.connect(e3.localAddr),
      e3.accept(),
    ]).catch((err) => err);
    t.assert(result instanceof Error);
  } finally {
    e1.close(0, "done");
    e2.close(0, "done");
    e3.close(0, "done");
  }
});

test("second hit", async (t) => {
  t.timeout(100);

  const k1 = EndpointKey.generate();
  const k2 = EndpointKey.generate();

  const hits = new Set();
  const secondHit = new Allower((key) => {
    const keyString = key.toString("hex");
    const hit = hits.has(keyString);
    hits.add(keyString);
    return hit;
  });

  const allowAll = new Allower(() => true);

  const e1 = new Endpoint("[::1]:0", k1, allowAll);
  const e2 = new Endpoint("[::1]:0", k2, secondHit);

  try {
    const accepts = e2.accept();
    const result = await e1.connect(e2.localAddr).catch((err) => err);
    t.assert(result instanceof Error);

    await Promise.all([e1.connect(e2.localAddr), accepts]);
  } finally {
    e1.close(0, "done");
    e2.close(0, "done");
  }
});
