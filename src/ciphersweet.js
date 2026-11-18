// CipherSweet "FIPSCrypto" backend on WebCrypto only.
// Wire format and key derivation match paragonie/ciphersweet (PHP), the reference implementation.
// Text is UTF-8. (ciphersweet-js uses Latin-1 and corrupts non-Latin-1 text.)

const subtle = crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

const HEADER = "fips:";
const SALT = 32, NONCE = 16, MAC = 48;
const DS_BIDX = new Uint8Array(32).fill(126);
const DS_FENC = new Uint8Array(32).fill(180);

export const utf8 = (s) => (typeof s === "string" ? enc.encode(s) : s);

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) out.set(p, i), (i += p.length);
  return out;
};

// 4-byte LE count, then each piece as 8-byte LE length + bytes.
function pack(pieces) {
  const head = new Uint8Array(4);
  new DataView(head.buffer).setUint32(0, pieces.length, true);
  return concat(head, ...pieces.flatMap((p) => {
    const len = new Uint8Array(8);
    new DataView(len.buffer).setBigUint64(0, BigInt(p.length), true);
    return [len, p];
  }));
}

const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

const b64url = (b) => {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_");
};
const unb64url = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

async function hkdf(ikm, salt, info) {
  const k = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-384", salt, info: utf8(info) }, k, 256));
}

const hmacKey = (raw, hash, usage) => subtle.importKey("raw", raw, { name: "HMAC", hash }, false, usage);

async function hmac(hash, key, msg) {
  return new Uint8Array(await subtle.sign("HMAC", await hmacKey(key, hash, ["sign"]), msg));
}

async function pbkdf2(password, salt, iterations, bits) {
  const k = await subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-384", salt, iterations }, k, bits));
}

async function aesCtr(key, nonce, data) {
  const k = await subtle.importKey("raw", key, "AES-CTR", false, ["encrypt"]);
  return new Uint8Array(await subtle.encrypt({ name: "AES-CTR", counter: nonce, length: 128 }, k, data));
}

/** Per-column encryption key: HKDF(root, salt=table, info=DS_FENC || column). */
export const fieldKey = (root, table, column) => hkdf(root, utf8(table), concat(DS_FENC, utf8(column)));

/** Per-column blind index root key: HKDF(root, salt=table, info=DS_BIDX || column). */
export const blindIndexRootKey = (root, table, column) => hkdf(root, utf8(table), concat(DS_BIDX, utf8(column)));

/** Encrypt bytes or a string. Returns "fips:" + base64url(salt | nonce | mac | ciphertext). */
export async function encrypt(key, plaintext, aad = "") {
  const salt = crypto.getRandomValues(new Uint8Array(SALT));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE));
  const ct = await aesCtr(await hkdf(key, salt, "AES-256-CTR"), nonce, utf8(plaintext));
  const mac = await hmac("SHA-384", await hkdf(key, salt, "HMAC-SHA-384"),
    concat(pack([utf8(HEADER), salt, nonce, ct]), utf8(aad)));
  return HEADER + b64url(concat(salt, nonce, mac, ct));
}

/** Decrypt to bytes. Throws on a bad header or MAC. */
export async function decryptBytes(key, ciphertext, aad = "") {
  if (typeof ciphertext !== "string" || !ciphertext.startsWith(HEADER)) throw new Error("Invalid ciphertext header");
  const raw = unb64url(ciphertext.slice(HEADER.length));
  if (raw.length < SALT + NONCE + MAC) throw new Error("Ciphertext too short");
  const salt = raw.subarray(0, SALT);
  const nonce = raw.subarray(SALT, SALT + NONCE);
  const mac = raw.subarray(SALT + NONCE, SALT + NONCE + MAC);
  const ct = raw.subarray(SALT + NONCE + MAC);
  const macKey = await hmacKey(await hkdf(key, salt, "HMAC-SHA-384"), "SHA-384", ["verify"]);
  // subtle.verify compares in constant time
  if (!(await subtle.verify("HMAC", macKey, mac, concat(pack([utf8(HEADER), salt, nonce, ct]), utf8(aad))))) {
    throw new Error("Invalid MAC");
  }
  return aesCtr(await hkdf(key, salt, "AES-256-CTR"), nonce, ct);
}

export const decrypt = async (key, ciphertext, aad = "") => dec.decode(await decryptBytes(key, ciphertext, aad));

/**
 * Blind index for one column value, as hex. Matches EncryptedRow::calcBlindIndex.
 * `fast` uses PBKDF2 with 1 iteration; slow uses `iterations` (min 50000).
 */
export async function blindIndex(root, table, column, name, value, { bits = 256, fast = false, iterations = 50000 } = {}) {
  if (bits % 8 || bits < 8 || bits > 512) throw new Error("Blind index bits must be a multiple of 8, from 8 to 512");
  const subKey = await hmac("SHA-256", await blindIndexRootKey(root, table, column),
    pack([utf8(table), utf8(column), utf8(name)]));
  return toHex(await pbkdf2(utf8(value), subKey, fast ? 1 : Math.max(iterations, 50000), bits));
}

/** Transformations, applied to the value before hashing. Names match CipherSweet. */
export const transforms = {
  // PHP strtolower: ASCII only. Pass your own (s) => s.toLowerCase() for Unicode (not PHP-compatible).
  lowercase: (s) => s.replace(/[A-Z]/g, (c) => c.toLowerCase()),
  lastFourDigits: (s) => s.replace(/[^0-9]/g, "").slice(-4).padStart(4, "0"),
};
