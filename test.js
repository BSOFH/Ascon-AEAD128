// test.js
const {
  asconAEAD128Encrypt,
  asconAEAD128Decrypt,
} = require("./ascon-aead128");

// helper: hex ↔ Uint8Array
function hexToU8(hex) {
  if (hex.length % 2) throw new Error("bad hex");
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return arr;
}
function u8ToHex(u8) {
  return Array.from(u8).map(b => b.toString(16).padStart(2, "0")).join("");
}

// sample values (you can replace with official KATs)
const key   = hexToU8("000102030405060708090a0b0c0d0e0f");
const nonce = hexToU8("000102030405060708090a0b0c0d0e0f");
const ad    = hexToU8("0a0b0c0d0e0f");
const msg   = hexToU8("00112233445566778899aabbccddeeff");

// Encrypt
const { ciphertext, tag } = asconAEAD128Encrypt(key, nonce, ad, msg);
console.log("Ciphertext:", u8ToHex(ciphertext));
console.log("Tag:       ", u8ToHex(tag));

// Decrypt
const decrypted = asconAEAD128Decrypt(key, nonce, ad, ciphertext, tag);
if (decrypted === null) {
  console.error("!! Authentication failed");
} else {
  console.log("Plaintext: ", u8ToHex(decrypted));
}
