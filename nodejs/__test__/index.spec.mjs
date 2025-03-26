import test from 'ava'

import { EndpointKey } from '../index.js'

test('generate and round trip a key', (t) => {
  const pem1 = EndpointKey.generate().toString()
  const pem2 = (new EndpointKey(pem1)).toString()
  t.is(pem1, pem2)
})
