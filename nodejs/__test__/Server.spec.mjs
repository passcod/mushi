import test from "ava";

import { Identity, Server, millisUntilExpiry } from "../index.js";

// Bind IPv4 loopback: not every runner has IPv6 configured.
const BIND = "127.0.0.1:0";

function makeServer() {
  const cert = Identity.generate().issue();
  return { server: new Server(BIND, cert), cert };
}

test("binds and reports its address", (t) => {
  const { server } = makeServer();
  try {
    t.regex(server.localAddr, /^127\.0\.0\.1:\d+$/);
    t.not(server.localAddr, "127.0.0.1:0");
    t.is(server.openConnections, 0);
  } finally {
    server.close(0, "done");
  }
});

test("reports handshake stats", (t) => {
  const { server } = makeServer();
  try {
    const stats = server.stats;
    t.is(stats.acceptedHandshakes, 0);
    t.is(stats.refusedHandshakes, 0);
    t.is(typeof stats.ignoredHandshakes, "number");
  } finally {
    server.close(0, "done");
  }
});

test("serves the certificate it was given", (t) => {
  const { server, cert } = makeServer();
  try {
    t.is(server.certificate.hashHex, cert.hashHex);
  } finally {
    server.close(0, "done");
  }
});

test("swaps the certificate without rebinding", (t) => {
  const { server, cert } = makeServer();
  try {
    const addr = server.localAddr;
    const next = Identity.generate().issue();

    server.setCertificate(next);
    t.is(server.certificate.hashHex, next.hashHex);
    t.not(server.certificate.hashHex, cert.hashHex);
    t.is(server.localAddr, addr);
  } finally {
    server.close(0, "done");
  }
});

test("rejects an unknown congestion controller", (t) => {
  const cert = Identity.generate().issue();
  t.throws(() => new Server(BIND, cert, "nonsense"));

  const ok = new Server(BIND, cert, "bbr");
  ok.close(0, "done");
});

test("counts down to expiry", (t) => {
  const cert = Identity.generate().issue(3600);
  const remaining = millisUntilExpiry(cert);

  t.true(remaining > 0);
  t.true(remaining <= 3600 * 1000);
});
