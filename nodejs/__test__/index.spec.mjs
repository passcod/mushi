import test from "ava";

import { EndpointKey } from "../index.js";

test("generate and round trip a key", (t) => {
  const pem1 = EndpointKey.generate().privateKeyPem;
  const pem2 = new EndpointKey(pem1).privateKeyPem;
  t.is(pem1, pem2);
});
