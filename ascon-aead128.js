// ascon-aead128.js
// NIST SP 800-232 compliant Ascon-AEAD128 encryption (enc)
// Input/Output are Uint8Array. Requires Node 12+ (BigInt).

// ====== bit utilities (64-bit BigInt) ======
const MASK64 = (1n << 64n) - 1n;
function rotr64(x, n) {
  n = BigInt(n & 63);
  return ((x >> n) | ((x << (64n - n)) & MASK64)) & MASK64;
}
function load64le(bytes, off = 0) {
  return (
    BigInt(bytes[off + 0])       |
    (BigInt(bytes[off + 1]) << 8n) |
    (BigInt(bytes[off + 2]) << 16n) |
    (BigInt(bytes[off + 3]) << 24n) |
    (BigInt(bytes[off + 4]) << 32n) |
    (BigInt(bytes[off + 5]) << 40n) |
    (BigInt(bytes[off + 6]) << 48n) |
    (BigInt(bytes[off + 7]) << 56n)
  ) & MASK64;
}
function store64le(x, out, off = 0) {
  out[off + 0] = Number(x & 0xffn); x >>= 8n;
  out[off + 1] = Number(x & 0xffn); x >>= 8n;
  out[off + 2] = Number(x & 0xffn); x >>= 8n;
  out[off + 3] = Number(x & 0xffn); x >>= 8n;
  out[off + 4] = Number(x & 0xffn); x >>= 8n;
  out[off + 5] = Number(x & 0xffn); x >>= 8n;
  out[off + 6] = Number(x & 0xffn); x >>= 8n;
  out[off + 7] = Number(x & 0xffn);
}

// ====== Ascon constants (Table 5) & IV (Table 14) ======
const ROUND_CONSTS = [
  0x3cn, 0x2dn, 0x1en, 0x0fn,
  0xf0n, 0xe1n, 0xd2n, 0xc3n,
  0xb4n, 0xa5n, 0x96n, 0x87n,
  0x78n, 0x69n, 0x5an, 0x4bn
]; // applied to S2 low byte
const IV_AEAD128 = 0x00001000808c0001n; // Ascon-AEAD128 IV

// ====== Ascon permutation (p[rounds]) ======
function asconPermutation(S, rounds) {
  // S is an array of five 64-bit BigInts [S0..S4]
  // round constants c_i = const[16 - rounds + i]
  for (let i = 0; i < rounds; i++) {
    const rc = ROUND_CONSTS[16 - rounds + i] & 0xffn;
    // p_C: add to S2 (low 8 bits; upper 56 are zero in c)
    S[2] ^= rc;

    // p_S: 64 parallel 5-bit S-boxes via bit-sliced boolean formula (Eq. 7)
    const x0 = S[0], x1 = S[1], x2 = S[2], x3 = S[3], x4 = S[4];
    const y0 = (x4 & x1) ^ x3 ^ (x2 & x1) ^ x2 ^ (x1 & x0) ^ x1 ^ x0;
    const y1 = x4 ^ (x3 & x2) ^ (x3 & x1) ^ x3 ^ (x2 & x1) ^ x2 ^ x1 ^ x0;
    const y2 = (x4 & x3) ^ x4 ^ x2 ^ x1 ^ MASK64; // XOR with 1 -> flip all bits
    const y3 = (x4 & x0) ^ x4 ^ (x3 & x0) ^ x3 ^ x2 ^ x1 ^ x0;
    const y4 = (x4 & x1) ^ x4 ^ x3 ^ (x1 & x0) ^ x1;
    S[0] = y0 & MASK64;
    S[1] = y1 & MASK64;
    S[2] = y2 & MASK64;
    S[3] = y3 & MASK64;
    S[4] = y4 & MASK64;

    // p_L: linear diffusion (Eq. 8–12)
    S[0] = (S[0] ^ rotr64(S[0], 19) ^ rotr64(S[0], 28)) & MASK64;
    S[1] = (S[1] ^ rotr64(S[1], 61) ^ rotr64(S[1], 39)) & MASK64;
    S[2] = (S[2] ^ rotr64(S[2], 1)  ^ rotr64(S[2], 6))  & MASK64;
    S[3] = (S[3] ^ rotr64(S[3], 10) ^ rotr64(S[3], 17)) & MASK64;
    S[4] = (S[4] ^ rotr64(S[4], 7)  ^ rotr64(S[4], 41)) & MASK64;
  }
}

// ====== helpers: parse & pad at rate r=128 bits (16 bytes) ======
function splitBlocks16(u8) {
  const fullBlocks = Math.floor(u8.length / 16);
  const rem = u8.length - fullBlocks * 16;
  return { fullBlocks, rem };
}

function readBlock128(u8, off = 0) {
  // returns [w0, w1] (two 64-bit LE words)
  return [load64le(u8, off), load64le(u8, off + 8)];
}

function readPartial128WithPad(u8, off, rem) {
  // Build two 64-bit words from rem bytes and apply Ascon pad:
  // y = x ^ (1 << (8*remBytes))  (Append bit '1' then zeros to fill 128 bits)
  let w0 = 0n, w1 = 0n;
  let i = 0;
  // first up to 8 bytes -> w0
  for (; i < Math.min(rem, 8); i++) {
    w0 |= BigInt(u8[off + i]) << (8n * BigInt(i));
  }
  // next up to 8 bytes -> w1
  for (; i < rem; i++) {
    const j = i - 8;
    w1 |= BigInt(u8[off + i]) << (8n * BigInt(j));
  }
  // padding bit at byte index 'rem'
  if (rem < 16) {
    if (rem < 8) {
      w0 ^= 1n << (8n * BigInt(rem));
    } else {
      const j = rem - 8;
      w1 ^= 1n << (8n * BigInt(j));
    }
  } else {
    // when rem==16, parse() would have produced empty last block;
    // but we only call this for 0 <= rem < 16
  }
  return [w0 & MASK64, w1 & MASK64];
}

function writeBlock128(out, off, w0, w1) {
  store64le(w0, out, off);
  store64le(w1, out, off + 8);
}

function writePartial128(out, off, w0, w1, rem) {
  // write exactly 'rem' bytes from (w0||w1) little-endian
  let tmp = new Uint8Array(16);
  writeBlock128(tmp, 0, w0, w1);
  out.set(tmp.subarray(0, rem), off);
}

// ====== public API ======
/**
 * Ascon-AEAD128 encryption
 * @param {Uint8Array} key  16 bytes
 * @param {Uint8Array} nonce 16 bytes (must be unique per key)
 * @param {Uint8Array} ad associated data (may be empty)
 * @param {Uint8Array} plaintext message (may be empty)
 * @returns {{ciphertext: Uint8Array, tag: Uint8Array}}
 */
function asconAEAD128Encrypt(key, nonce, ad, plaintext) {
  if (!(key instanceof Uint8Array) || key.length !== 16) {
    throw new Error("key must be 16-byte Uint8Array");
  }
  if (!(nonce instanceof Uint8Array) || nonce.length !== 16) {
    throw new Error("nonce must be 16-byte Uint8Array");
  }
  ad = ad || new Uint8Array(0);
  plaintext = plaintext || new Uint8Array(0);

  // Load K and N as two 64-bit little-endian words each
  const K0 = load64le(key, 0),   K1 = load64le(key, 8);
  const N0 = load64le(nonce, 0), N1 = load64le(nonce, 8);

  // State S = [S0..S4] = IV || K || N
  const S = [IV_AEAD128 & MASK64, K0, K1, N0, N1];

  // Initialization: p[12], then S ^= (0^192 || K)
  asconPermutation(S, 12);
  S[3] ^= K0; S[4] ^= K1;

  // Process Associated Data (only if |AD| > 0)
  if (ad.length > 0) {
    const { fullBlocks, rem } = splitBlocks16(ad);
    // full 16-byte blocks
    for (let b = 0; b < fullBlocks; b++) {
      const [w0, w1] = readBlock128(ad, b * 16);
      S[0] ^= w0; S[1] ^= w1;
      asconPermutation(S, 8);
    }
    // last partial with padding
    const [pw0, pw1] = readPartial128WithPad(ad, fullBlocks * 16, rem);
    S[0] ^= pw0; S[1] ^= pw1;
    asconPermutation(S, 8);
  }
  // Domain separation: S ^= (0^319 || 1)
  S[4] ^= 1n;

  // Encrypt plaintext
  const C = new Uint8Array(plaintext.length);
  const { fullBlocks: m, rem: r } = splitBlocks16(plaintext);
  for (let b = 0; b < m; b++) {
    const [w0, w1] = readBlock128(plaintext, b * 16);
    S[0] ^= w0; S[1] ^= w1;
    // output Ci = S[0..127]
    writeBlock128(C, b * 16, S[0], S[1]);
    asconPermutation(S, 8);
  }
  // last partial block
  if (r > 0) {
    // pad P_n and absorb
    const [pw0, pw1] = readPartial128WithPad(plaintext, m * 16, r);
    S[0] ^= pw0; S[1] ^= pw1;
    // C_n = S[0..ell-1] -> write r bytes
    writePartial128(C, m * 16, S[0], S[1], r);
  } else {
    // If there is no partial block, parse() defines an empty last block,
    // and we still need to absorb pad(empty, 128) before finalization.
    // pad(empty,128) is XOR 1 into the very first byte (LSB of S0).
    S[0] ^= 1n;
  }

  // Finalization: S ^= (0^128 || K || 0^64), p[12], T = S[192..319] ^ K
  S[2] ^= K0; S[3] ^= K1; // XOR K into S2||S3 (bits 128..255)
  asconPermutation(S, 12);
  const T0 = (S[3] ^ K0) & MASK64;
  const T1 = (S[4] ^ K1) & MASK64;

  const tag = new Uint8Array(16);
  store64le(T0, tag, 0);
  store64le(T1, tag, 8);

  return { ciphertext: C, tag };
}

// ascon-aead128.js (continuing from encrypt implementation above)

function asconAEAD128Decrypt(key, nonce, ad, ciphertext, tag) {
  if (!(key instanceof Uint8Array) || key.length !== 16) {
    throw new Error("key must be 16-byte Uint8Array");
  }
  if (!(nonce instanceof Uint8Array) || nonce.length !== 16) {
    throw new Error("nonce must be 16-byte Uint8Array");
  }
  if (!(tag instanceof Uint8Array) || tag.length !== 16) {
    throw new Error("tag must be 16-byte Uint8Array");
  }
  ad = ad || new Uint8Array(0);
  ciphertext = ciphertext || new Uint8Array(0);

  // Load K and N
  const K0 = load64le(key, 0),   K1 = load64le(key, 8);
  const N0 = load64le(nonce, 0), N1 = load64le(nonce, 8);

  // State S = IV || K || N
  const S = [IV_AEAD128 & MASK64, K0, K1, N0, N1];

  // Initialization
  asconPermutation(S, 12);
  S[3] ^= K0; S[4] ^= K1;

  // Process Associated Data
  if (ad.length > 0) {
    const { fullBlocks, rem } = splitBlocks16(ad);
    for (let b = 0; b < fullBlocks; b++) {
      const [w0, w1] = readBlock128(ad, b * 16);
      S[0] ^= w0; S[1] ^= w1;
      asconPermutation(S, 8);
    }
    const [pw0, pw1] = readPartial128WithPad(ad, fullBlocks * 16, rem);
    S[0] ^= pw0; S[1] ^= pw1;
    asconPermutation(S, 8);
  }
  // Domain separation
  S[4] ^= 1n;

  // Decrypt ciphertext
  const P = new Uint8Array(ciphertext.length);
  const { fullBlocks: n, rem: r } = splitBlocks16(ciphertext);
  for (let b = 0; b < n; b++) {
    const [c0, c1] = readBlock128(ciphertext, b * 16);
    const p0 = S[0] ^ c0;
    const p1 = S[1] ^ c1;
    writeBlock128(P, b * 16, p0, p1);
    S[0] = c0;
    S[1] = c1;
    asconPermutation(S, 8);
  }
  if (r > 0) {
    const tmp = new Uint8Array(16);
    const cLast = ciphertext.subarray(n * 16);
    tmp.set(cLast, 0);
    const c0 = load64le(tmp, 0);
    const c1 = load64le(tmp, 8);
    // P_n = S[0..ell-1] ^ C_n
    for (let i = 0; i < r; i++) {
      const byte = (i < 8)
        ? Number((S[0] >> (8n * BigInt(i))) & 0xffn)
        : Number((S[1] >> (8n * BigInt(i - 8))) & 0xffn);
      P[n * 16 + i] = byte ^ cLast[i];
    }
    // absorb pad
    if (r < 8) {
      S[0] ^= c0 & ((1n << (8n * BigInt(r))) - 1n);
      S[0] ^= 1n << (8n * BigInt(r));
      S[1] ^= c1;
    } else {
      S[0] ^= c0;
      S[1] ^= c1 & ((1n << (8n * BigInt(r - 8))) - 1n);
      S[1] ^= 1n << (8n * BigInt(r - 8));
    }
  } else {
    // empty last block => absorb pad(empty,128)
    S[0] ^= 1n;
  }

  // Finalization
  S[2] ^= K0; S[3] ^= K1;
  asconPermutation(S, 12);
  const T0 = (S[3] ^ K0) & MASK64;
  const T1 = (S[4] ^ K1) & MASK64;
  const Tcalc = new Uint8Array(16);
  store64le(T0, Tcalc, 0);
  store64le(T1, Tcalc, 8);

  // Verify tag in constant time
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= (Tcalc[i] ^ tag[i]);
  if (diff !== 0) {
    return null; // authentication failed
  }

  return P;
}


// Export for Node / bundlers
module.exports = { asconAEAD128Encrypt, asconAEAD128Decrypt };
