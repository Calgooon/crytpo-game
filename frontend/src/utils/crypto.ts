import CryptoJS from 'crypto-js';
const { SHA512 } = CryptoJS;
import * as ed25519 from '@noble/ed25519';

// Set up SHA-512 for ed25519 using crypto-js
ed25519.etc.sha512Sync = (...messages) => {
  const message = messages.map(m => {
    if (typeof m === 'string') {
      return new TextEncoder().encode(m);
    }
    return m;
  });
  const concatenated = new Uint8Array(message.reduce((acc, curr) => acc + curr.length, 0));
  let offset = 0;
  for (const m of message) {
    concatenated.set(m, offset);
    offset += m.length;
  }
  return new Uint8Array(CryptoJS.enc.Hex.parse(SHA512(CryptoJS.lib.WordArray.create(concatenated)).toString()).words);
}; 