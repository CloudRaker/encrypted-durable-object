import { DurableObject } from "cloudflare:workers";
import * as cs from "./ciphersweet.js";

export { cs as ciphersweet };

const ROWID = "__edo_rowid";
const KV_PREFIX = "__edo_kv:";
const WRAPPED_KEY = "__edo_wrapped_root_key";

// Table and column names go into SQL text, so allow plain identifiers only.
const id = (s) => {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(s)) throw new Error(`Invalid SQL identifier: ${JSON.stringify(s)}`);
  return `"${s}"`;
};

const fromHex = (h) => {
  if (!/^([0-9a-f]{2})+$/i.test(h)) throw new Error("Expected a hex string");
  return Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16));
};

/** Normalize `static encrypted` into { table: { column: [index, ...] } }. */
function compileSchema(schema = {}) {
  const out = {};
  for (const [table, cols] of Object.entries(schema)) {
    id(table);
    out[table] = {};
    for (const [col, spec] of Object.entries(cols)) {
      id(col);
      const list = spec === true ? [] : [spec.index ?? spec.indexes ?? []].flat();
      out[table][col] = list.map((ix, n) => {
        const name = ix.name ?? (n === 0 ? `${col}_idx` : undefined);
        if (!name) throw new Error(`${table}.${col}: every index after the first needs a name`);
        const fns = (ix.transforms ?? []).map((t) => {
          if (typeof t === "function") return t;
          if (!cs.transforms[t]) throw new Error(`Unknown transform "${t}"`);
          return cs.transforms[t];
        });
        return { name: id(name) && name, bits: ix.bits ?? 32, fast: ix.fast ?? true, iterations: ix.iterations, fns };
      });
    }
  }
  return out;
}

const transform = (ix, v) => ix.fns.reduce((s, f) => f(s), v);

/**
 * A Durable Object whose SQLite rows and KV values are encrypted with CipherSweet.
 *
 * Subclass it, declare `static encrypted`, and implement `rootKey()`.
 * Then use `this.db` for encrypted tables and `this.kv` for encrypted key-value storage.
 */
export class EncryptedDurableObject extends DurableObject {
  #root;
  #schema;

  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.#schema = compileSchema(this.constructor.encrypted);
    ctx.blockConcurrencyWhile(async () => {
      await null; // let the subclass constructor finish before rootKey() runs
      const k = await this.rootKey();
      const root = typeof k === "string" ? fromHex(k) : new Uint8Array(k);
      if (root.length !== 32) throw new Error("rootKey() must return 32 bytes");
      this.#root = root;
    });
    this.db = new EncryptedTables(this.sql, this.#schema, () => this.#root);
    this.kv = new EncryptedKV(ctx.storage, () => this.#root);
  }

  /** Return the 32-byte root key (Uint8Array, ArrayBuffer or hex). Called once per activation. */
  async rootKey() {
    throw new Error(`${this.constructor.name} must implement rootKey()`);
  }
}

class EncryptedTables {
  #sql; #schema; #root;
  constructor(sql, schema, root) {
    this.#sql = sql;
    this.#schema = schema;
    this.#root = root;
  }

  #cols(table) {
    return this.#schema[table] ?? {};
  }

  async #fieldKey(table, col) {
    // ponytail: derives the column key on every call (~µs). Cache per (table, col) if profiling says so.
    return cs.fieldKey(this.#root(), table, col);
  }

  #index(table, col, ix, value) {
    return cs.blindIndex(this.#root(), table, col, ix.name, transform(ix, value), ix);
  }

  async #encrypt(table, row) {
    const out = { ...row };
    for (const [col, indexes] of Object.entries(this.#cols(table))) {
      const v = row[col];
      if (v === undefined) continue;
      if (v === null) {
        for (const ix of indexes) out[ix.name] = null;
        continue;
      }
      if (typeof v !== "string") throw new TypeError(`${table}.${col} is encrypted and must be a string (got ${typeof v})`);
      out[col] = await cs.encrypt(await this.#fieldKey(table, col), v);
      for (const ix of indexes) out[ix.name] = await this.#index(table, col, ix, v);
    }
    return out;
  }

  /** Build a WHERE clause. Encrypted columns use their blind index; `checks` drop index false positives. */
  async #where(table, where) {
    const cols = this.#cols(table);
    const byIndex = {};
    for (const [col, indexes] of Object.entries(cols)) for (const ix of indexes) byIndex[ix.name] = [col, ix];
    const clauses = [], params = [], checks = [];
    for (const [k, v] of Object.entries(where)) {
      let target = byIndex[k];
      if (!target && cols[k]) {
        if (!cols[k].length) throw new Error(`${table}.${k} is encrypted and has no blind index, so it cannot be searched`);
        target = [k, cols[k][0]];
      }
      if (v === null) {
        clauses.push(`${id(target ? target[1].name : k)} IS NULL`);
      } else if (target) {
        const [col, ix] = target;
        clauses.push(`${id(ix.name)} = ?`);
        params.push(await this.#index(table, col, ix, v));
        const want = transform(ix, v);
        checks.push((row) => row[col] != null && transform(ix, row[col]) === want);
      } else {
        clauses.push(`${id(k)} = ?`);
        params.push(v);
      }
    }
    return { sql: clauses.length ? ` WHERE ${clauses.join(" AND ")}` : "", params, checks };
  }

  /** Decrypt the encrypted columns of a row read with raw SQL. Other columns pass through. */
  async decrypt(table, row) {
    const out = { ...row };
    delete out[ROWID];
    for (const col of Object.keys(this.#cols(table))) {
      if (typeof row[col] === "string") out[col] = await cs.decrypt(await this.#fieldKey(table, col), row[col]);
    }
    return out;
  }

  async #match(table, where) {
    const w = await this.#where(table, where);
    const rows = this.#sql.exec(`SELECT rowid AS ${ROWID}, * FROM ${id(table)}${w.sql}`, ...w.params).toArray();
    const out = [];
    for (const r of rows) {
      const plain = await this.decrypt(table, r);
      if (w.checks.every((c) => c(plain))) out.push([r[ROWID], plain]);
    }
    return { w, out };
  }

  #changes() {
    return this.#sql.exec("SELECT changes() AS n").one().n;
  }

  /** Insert one row. Returns the new rowid. */
  async insert(table, row) {
    const enc = await this.#encrypt(table, row);
    const keys = Object.keys(enc);
    this.#sql.exec(
      `INSERT INTO ${id(table)} (${keys.map(id).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`,
      ...keys.map((k) => enc[k]),
    );
    return this.#sql.exec("SELECT last_insert_rowid() AS id").one().id;
  }

  /**
   * Find rows by equality. Encrypted columns must have a blind index.
   * Rows are decrypted. Index collisions are removed after decryption.
   */
  async find(table, where = {}, { limit } = {}) {
    // ponytail: LIMIT is applied after the collision filter, so the SQL query reads every candidate row.
    const rows = (await this.#match(table, where)).out.map(([, r]) => r);
    return limit === undefined ? rows : rows.slice(0, limit);
  }

  async get(table, where) {
    return (await this.find(table, where, { limit: 1 }))[0] ?? null;
  }

  /** Update matching rows. Encrypted columns in `patch` are re-encrypted and re-indexed. Returns the row count. */
  async update(table, where, patch) {
    const enc = await this.#encrypt(table, patch);
    const keys = Object.keys(enc);
    if (!keys.length) return 0;
    const { w, out } = await this.#match(table, where);
    if (!out.length) return 0;
    // The WHERE clause is applied again, so a row changed by a concurrent request during decryption is skipped.
    this.#sql.exec(
      `UPDATE ${id(table)} SET ${keys.map((k) => `${id(k)} = ?`).join(", ")}` +
        ` WHERE rowid IN (SELECT value FROM json_each(?))${w.sql.replace(" WHERE ", " AND ")}`,
      ...keys.map((k) => enc[k]), JSON.stringify(out.map(([rowid]) => rowid)), ...w.params,
    );
    return this.#changes(); // rowsWritten also counts SQLite index writes
  }

  /** Delete matching rows. Returns the row count. */
  async delete(table, where) {
    const { w, out } = await this.#match(table, where);
    if (!out.length) return 0;
    this.#sql.exec(
      `DELETE FROM ${id(table)} WHERE rowid IN (SELECT value FROM json_each(?))${w.sql.replace(" WHERE ", " AND ")}`,
      JSON.stringify(out.map(([rowid]) => rowid)), ...w.params,
    );
    return this.#changes();
  }

  /** Blind index value for raw SQL, e.g. `WHERE email_idx = ?`. */
  async blindIndex(table, column, value, indexName) {
    const indexes = this.#cols(table)[column];
    if (!indexes?.length) throw new Error(`${table}.${column} has no blind index`);
    const ix = indexName ? indexes.find((i) => i.name === indexName) : indexes[0];
    if (!ix) throw new Error(`Unknown index ${indexName}`);
    return this.#index(table, column, ix, value);
  }
}

/** Encrypted wrapper over ctx.storage get/put. Values are JSON. Keys stay plaintext. */
class EncryptedKV {
  #storage; #root;
  constructor(storage, root) {
    this.#storage = storage;
    this.#root = root;
  }

  // The storage key is the AAD, so a value copied to another key fails to decrypt.
  #key = () => cs.fieldKey(this.#root(), "__edo_kv", "value");

  async get(key) {
    const ct = await this.#storage.get(KV_PREFIX + key);
    return ct === undefined ? undefined : JSON.parse(await cs.decrypt(await this.#key(), ct, key));
  }

  async put(key, value) {
    await this.#storage.put(KV_PREFIX + key, await cs.encrypt(await this.#key(), JSON.stringify(value), key));
  }

  async delete(key) {
    return this.#storage.delete(KV_PREFIX + key);
  }

  /** Returns a Map of decrypted values. Supports `prefix` and `limit`. */
  async list({ prefix = "", limit } = {}) {
    const raw = await this.#storage.list({ prefix: KV_PREFIX + prefix, limit });
    const k = await this.#key(), out = new Map();
    for (const [sk, ct] of raw) {
      const key = sk.slice(KV_PREFIX.length);
      out.set(key, JSON.parse(await cs.decrypt(k, ct, key)));
    }
    return out;
  }
}

/**
 * Envelope encryption: a random root key per Durable Object, stored wrapped.
 * `wrap` and `unwrap` call your KMS (AWS KMS, GCP KMS, Vault, a local KEK, ...).
 * The wrapped blob can be any structured-clonable value.
 */
export async function wrappedRootKey(ctx, { wrap, unwrap }) {
  const blob = await ctx.storage.get(WRAPPED_KEY);
  if (blob !== undefined) return unwrap(blob);
  const key = crypto.getRandomValues(new Uint8Array(32));
  await ctx.storage.put(WRAPPED_KEY, await wrap(key));
  return key;
}

/**
 * wrap/unwrap with AES-256-GCM under a key-encryption key from a secret (64 hex chars).
 * The Durable Object id is bound as AAD, so a wrapped key cannot be moved to another object.
 */
export function secretKek(ctx, secretHex) {
  const kek = crypto.subtle.importKey("raw", fromHex(secretHex), "AES-GCM", false, ["encrypt", "decrypt"]);
  const additionalData = new TextEncoder().encode(ctx.id.toString());
  return {
    async wrap(key) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, await kek, key);
      return { v: 1, iv, ct: new Uint8Array(ct) };
    },
    async unwrap({ iv, ct }) {
      return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData }, await kek, ct));
    },
  };
}
