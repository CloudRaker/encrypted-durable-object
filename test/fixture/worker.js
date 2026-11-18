import { EncryptedDurableObject, wrappedRootKey, secretKek } from "../../src/index.js";

export class Tenant extends EncryptedDurableObject {
  static encrypted = {
    contacts: {
      email: { index: { transforms: ["lowercase"], bits: 8 } }, // 8 bits: force collisions in tests
      ssn: { indexes: [{ name: "ssn_last4", transforms: ["lastFourDigits"], bits: 16 }] },
      notes: true,
    },
  };

  constructor(ctx, env) {
    super(ctx, env);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS contacts (
      id INTEGER PRIMARY KEY, name TEXT, email TEXT, email_idx TEXT, ssn TEXT, ssn_last4 TEXT, notes TEXT);
      CREATE INDEX IF NOT EXISTS contacts_email_idx ON contacts(email_idx);`);
  }

  rootKey() {
    return wrappedRootKey(this.ctx, secretKek(this.ctx, this.env.KEK));
  }

  raw() { return this.sql.exec("SELECT * FROM contacts").toArray(); }
  insert(row) { return this.db.insert("contacts", row); }
  find(where) { return this.db.find("contacts", where); }
  get(where) { return this.db.get("contacts", where); }
  update(where, patch) { return this.db.update("contacts", where, patch); }
  del(where) { return this.db.delete("contacts", where); }
  kvPut(k, v) { return this.kv.put(k, v); }
  kvGet(k) { return this.kv.get(k); }
  kvList(o) { return this.kv.list(o); }
  async kvRaw(k) { return this.ctx.storage.get("__edo_kv:" + k); }
}

export default {
  async fetch(req, env) {
    const { tenant, method, args } = await req.json();
    const stub = env.TENANT.get(env.TENANT.idFromName(tenant));
    try {
      const r = await stub[method](...args);
      return Response.json({ ok: r instanceof Map ? Object.fromEntries(r) : r ?? null });
    } catch (e) {
      return Response.json({ error: String(e.message ?? e) });
    }
  },
};
