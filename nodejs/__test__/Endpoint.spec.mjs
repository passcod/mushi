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
      (await s1.peerKey()).toString("base64"),
      k2.publicKeyPem
        .split("\n")
        .filter((line) => !line.includes("---"))
        .join("")
        .replace(/\s+/g, ""),
    );

    const s2 = await s2p;
    t.is(
      (await s2.peerKey()).toString("base64"),
      k1.publicKeyPem
        .split("\n")
        .filter((line) => !line.includes("---"))
        .join("")
        .replace(/\s+/g, ""),
    );
  } finally {
    e1.close(0, "done");
    e2.close(0, "done");
  }
});

test("datagram", async (t) => {
  t.timeout(100);

  const k1 = EndpointKey.generate();
  const k2 = EndpointKey.generate();

  const a = new Allower((key) => true);

  const e1 = new Endpoint("[::1]:0", k1, a);
  const e2 = new Endpoint("[::1]:0", k2, a);

  try {
    const [s1, s2] = await Promise.all([e1.connect(e2.localAddr), e2.accept()]);

    s1.sendDatagram(Buffer.from("Hello"));
    s2.sendDatagram(Buffer.from("World"));
    t.deepEqual(await s2.recvDatagram(), Buffer.from("Hello"));
    t.deepEqual(await s1.recvDatagram(), Buffer.from("World"));
  } finally {
    e1.close(0, "done");
    e2.close(0, "done");
  }
});

test("unidi", async (t) => {
  t.timeout(100);

  const k1 = EndpointKey.generate();
  const k2 = EndpointKey.generate();

  const a = new Allower((key) => true);

  const e1 = new Endpoint("[::1]:0", k1, a);
  const e2 = new Endpoint("[::1]:0", k2, a);

  try {
    const [s1, s2] = await Promise.all([e1.connect(e2.localAddr), e2.accept()]);

    const [us1, ur2] = await Promise.all([s1.openUni(), s2.acceptUni()]);
    const [ur1, us2] = await Promise.all([s1.acceptUni(), s2.openUni()]);

    await us1.write(Buffer.from("Hello"));
    await us2.write(Buffer.from("World"));

    t.deepEqual(await ur2.read(10), Buffer.from("Hello"));

    const buf = Buffer.alloc(5);
    await ur1.readBuf(buf);
    t.deepEqual(buf, Buffer.from("World"));
  } finally {
    e1.close(0, "done");
    e2.close(0, "done");
  }
});

test("bidi", async (t) => {
  t.timeout(100);

  const k1 = EndpointKey.generate();
  const k2 = EndpointKey.generate();

  const a = new Allower((key) => true);

  const e1 = new Endpoint("[::1]:0", k1, a);
  const e2 = new Endpoint("[::1]:0", k2, a);

  try {
    const [s1, s2] = await Promise.all([e1.connect(e2.localAddr), e2.accept()]);

    const [usr1, usr2] = await Promise.all([s1.openBi(), s2.acceptBi()]);

    const us1 = usr1.takeSend();
    const ur1 = usr1.takeRecv();
    const us2 = usr2.takeSend();
    const ur2 = usr2.takeRecv();

    await us1.write(Buffer.from("Hello"));
    await us2.write(Buffer.from("World"));

    t.deepEqual(await ur2.read(10), Buffer.from("Hello"));

    const buf = Buffer.alloc(5);
    await ur1.readBuf(buf);
    t.deepEqual(buf, Buffer.from("World"));
  } finally {
    e1.close(0, "done");
    e2.close(0, "done");
  }
});
