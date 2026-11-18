// Compatibility with the CipherSweet reference implementation.
// test/vectors.json was generated once by paragonie/ciphersweet (PHP), FIPSCrypto backend.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { encrypt, decrypt, fieldKey, blindIndex, transforms } from "../src/ciphersweet.js";

const v = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url)));
const root = Uint8Array.from(v.rootKey.match(/../g), (h) => parseInt(h, 16));
const key = await fieldKey(root, v.table, v.column);

for (const c of v.cases) {
  test(`reference vector ${JSON.stringify(c.value.slice(0, 20))}`, async () => {
    assert.equal(await decrypt(key, c.ciphertext), c.value, "decrypts reference ciphertext");
    for (const ix of v.indexes) {
      const input = ix.transforms.reduce((s, t) => transforms[t](s), c.value);
      assert.equal(await blindIndex(root, v.table, v.column, ix.name, input, ix), c.blindIndexes[ix.name], ix.name);
    }
    assert.equal(await decrypt(key, await encrypt(key, c.value)), c.value, "round trip");
  });
}

test("rejects wrong AAD, wrong key and tampering", async () => {
  const ct = await encrypt(key, "hello", "row-1");
  assert.equal(await decrypt(key, ct, "row-1"), "hello");
  await assert.rejects(decrypt(key, ct, "row-2"), /Invalid MAC/);
  await assert.rejects(decrypt(await fieldKey(root, v.table, "other"), ct, "row-1"), /Invalid MAC/);
  await assert.rejects(decrypt(key, ct.slice(0, -4) + "AAAA", "row-1"), /Invalid MAC/);
});
