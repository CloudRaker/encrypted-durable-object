// End-to-end tests in workerd through wrangler. Run: npm test
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { unstable_startWorker } from "wrangler";

let worker;
before(async () => {
  worker = await unstable_startWorker({ config: new URL("./fixture/wrangler.jsonc", import.meta.url).pathname });
  await worker.ready;
});
after(() => worker?.dispose());

const run = (tenant) => async (method, ...args) => {
  const r = await (await worker.fetch("http://x/", { method: "POST", body: JSON.stringify({ tenant, method, args }) })).json();
  if (r.error) throw new Error(r.error);
  return r.ok;
};
const fresh = () => run(crypto.randomUUID());

test("stores ciphertext and finds by blind index, case-insensitive", async () => {
  const t = fresh();
  await t("insert", { name: "Alice", email: "Alice@Example.com", ssn: "123-45-6789", notes: "日本語 🙂" });
  const [raw] = await t("raw");
  assert.match(raw.email, /^fips:/);
  assert.match(raw.ssn, /^fips:/);
  assert.ok(!JSON.stringify(raw).includes("Example"), "no plaintext on disk");
  const got = await t("get", { email: "alice@EXAMPLE.com" });
  assert.equal(got.email, "Alice@Example.com");
  assert.equal(got.notes, "日本語 🙂");
  assert.equal((await t("find", { ssn_last4: "6789" })).length, 1);
});

test("removes blind index collisions (8-bit index)", async () => {
  const t = fresh();
  for (let i = 0; i < 60; i++) await t("insert", { name: `u${i}`, email: `user${i}@x.com` });
  const idx = (await t("raw")).map((r) => r.email_idx);
  assert.ok(new Set(idx).size < idx.length, "test needs at least one collision");
  for (let i = 0; i < 60; i++) {
    const rows = await t("find", { email: `user${i}@x.com` });
    assert.deepEqual(rows.map((r) => r.name), [`u${i}`]);
  }
});

test("update and delete touch only the matching row", async () => {
  const t = fresh();
  for (let i = 0; i < 60; i++) await t("insert", { name: `u${i}`, email: `user${i}@x.com` });
  assert.equal(await t("update", { email: "user7@x.com" }, { email: "new@x.com", name: "seven" }), 1);
  assert.equal((await t("find", { email: "user7@x.com" })).length, 0);
  assert.equal((await t("get", { email: "NEW@x.com" })).name, "seven");
  assert.equal(await t("del", { email: "new@x.com" }), 1);
  assert.equal((await t("raw")).length, 59);
});

test("tenants are isolated", async () => {
  const a = fresh(), b = fresh();
  await a("insert", { email: "same@x.com", ssn: "000-00-1111" });
  await b("insert", { email: "same@x.com", ssn: "000-00-1111" });
  assert.notEqual((await a("raw"))[0].ssn_last4, (await b("raw"))[0].ssn_last4);
  assert.equal((await b("find", { email: "same@x.com" })).length, 1);
});

test("nulls, types and identifiers", async () => {
  const t = fresh();
  await t("insert", { name: "nobody", email: null });
  assert.equal((await t("get", { email: null })).name, "nobody");
  await assert.rejects(t("insert", { email: 42 }), /must be a string/);
  await assert.rejects(t("find", { notes: "x" }), /no blind index/);
  await assert.rejects(t("find", { "name; DROP TABLE contacts": "x" }), /Invalid SQL identifier/);
});

test("encrypted KV", async () => {
  const t = fresh();
  await t("kvPut", "settings", { theme: "dark", n: 1 });
  await t("kvPut", "session:1", "abc");
  assert.deepEqual(await t("kvGet", "settings"), { theme: "dark", n: 1 });
  assert.match(await t("kvRaw", "settings"), /^fips:/);
  assert.deepEqual(await t("kvList", { prefix: "session:" }), { "session:1": "abc" });
  assert.equal(await t("kvGet", "missing"), null);
});
