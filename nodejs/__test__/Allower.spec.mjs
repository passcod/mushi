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

// SKIPS: the tests work, the functions finish, but the test harness never shuts down

test.skip("keyset", async (t) => {
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

test.skip("second hit", async (t) => {
  t.timeout(200);
  t.plan(1);

  const k1 = EndpointKey.generate();
  const k2 = EndpointKey.generate();

  const hits = new Set();
  const secondHit = new Allower((key) => {
    const keyString = key.toString("hex");
    const hit = hits.has(keyString);
    console.log(keyString, hit);
    hits.add(keyString);
    return hit;
  });

  const allowAll = new Allower(() => true);
  const e1 = new WeakRef(new Endpoint("[::1]:0", k1, allowAll));
  const targetAddr = e1.deref().localAddr;

  (async () => {
    while (true) {
      console.log("accept");
      if (!(await e1.deref()?.accept())) {
        console.log("break");
        break;
      }
    }
  })();

  await (async () => {
    const e2 = new Endpoint("[::1]:0", k2, secondHit);
    try {
      const connR = await e2.connect(targetAddr).catch((err) => err);
      t.assert(connR instanceof Error);
    } finally {
      e2.close(0, "done");
      await e2.waitIdle();
    }
  })();

  await (async () => {
    const e3 = new Endpoint("[::1]:0", k1, secondHit);
    try {
      await e3.connect(targetAddr);
    } finally {
      e3.close(0, "done");
      await e3.waitIdle();
    }
  })();

  console.log("e1 close");
  e1.deref()?.close(0, "done");
  await e1.deref()?.waitIdle();
});
