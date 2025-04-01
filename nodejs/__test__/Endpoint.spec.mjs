import test from "ava";

import { EndpointKey, Allower, Endpoint } from "../index.js";

test("connection", async (t) => {
  t.plan(4);
  t.timeout(100);

  const k1 = EndpointKey.generate();
  const k2 = EndpointKey.generate();

  const a = new Allower((key) => true);

  const e1 = new Endpoint("[::1]:0", k1, a);
  const e2 = new Endpoint("[::1]:0", k2, a);

  try {
    const s1p = e1.connect(e2.localAddr);
    const s2p = e2.accept();

    t.assert(s1p);
    t.assert(s2p);

    const s1 = await s1p;
    t.is(
      s1.peerKey().toString("base64"),
      k2.publicKeyPem
        .split("\n")
        .filter((line) => !line.includes("---"))
        .join(""),
    );

    const s2 = await s2p;
    t.is(
      s2.peerKey().toString("base64"),
      k1.publicKeyPem
        .split("\n")
        .filter((line) => !line.includes("---"))
        .join(""),
    );
  } finally {
    e1.close(0, "done");
    e2.close(0, "done");
  }
});
