/**
 * webcrypto-comprehensive.js
 *
 * Demonstrates ALL encryption and hashing algorithms supported by the
 * Web Crypto API (window.crypto.subtle) in modern browsers (Chrome, Firefox,
 * Safari, Edge).
 *
 * Algorithms covered (per the W3C Web Cryptography API specification):
 *   Hashing   : SHA-1, SHA-256, SHA-384, SHA-512
 *   HMAC      : HMAC with each SHA variant
 *   Symmetric : AES-CBC, AES-CTR, AES-GCM
 *   Key wrap  : AES-KW
 *   Asymmetric: RSA-OAEP (encrypt/decrypt), RSA-PSS (sign/verify),
 *               RSASSA-PKCS1-v1_5 (sign/verify)
 *   Elliptic  : ECDSA (sign/verify), ECDH (key agreement)
 *   Derive    : PBKDF2, HKDF
 *   Random    : crypto.getRandomValues()
 *
 * Run in a browser console, or with Node >= 19 where globalThis.crypto
 * exposes the Web Crypto API:
 *
 *   node webcrypto-comprehensive.js
 *
 * Note: Node < 19 users may need:
 *   const { webcrypto } = require('crypto');
 *   globalThis.crypto = webcrypto;
 */

// ---------------------------------------------------------------------------
// Polyfill: make the script runnable with Node.js as well as a browser
// ---------------------------------------------------------------------------
if (typeof globalThis.crypto === 'undefined' || typeof globalThis.crypto.subtle === 'undefined') {
  try {
    const { webcrypto } = require('crypto');
    globalThis.crypto = webcrypto;
  } catch {
    throw new Error('Web Crypto API is not available in this environment.');
  }
}

const subtle = crypto.subtle;

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------
const enc = new TextEncoder();
const dec = new TextDecoder();

const plainText = 'Somebody is coding again!';
const plainBytes = enc.encode(plainText);
const password  = 'password';
const salt      = crypto.getRandomValues(new Uint8Array(16));

/** Convert an ArrayBuffer / TypedArray to a lowercase hex string. */
function toHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Log a result line, truncating hex strings that are very long. */
function log(label, value) {
  const str = typeof value === 'string' ? value : String(value);
  const display = str.length > 120 ? str.substring(0, 120) + '...' : str;
  console.log(`  ${label}: ${display}`);
}

/** Wrap an async operation with error handling and a section label. */
async function run(label, fn) {
  try {
    await fn();
  } catch (err) {
    console.log(`  ${label}: [ERROR] ${err.message}`);
  }
}

// ---------------------------------------------------------------------------
// 1. RANDOM NUMBER GENERATION  (crypto.getRandomValues)
// ---------------------------------------------------------------------------
console.log('\n================== RANDOM GENERATION ==================');

const rand16 = crypto.getRandomValues(new Uint8Array(16));
log('getRandomValues(Uint8Array 16)', toHex(rand16));

const rand32 = crypto.getRandomValues(new Uint8Array(32));
log('getRandomValues(Uint8Array 32)', toHex(rand32));

const randUUID = crypto.randomUUID();          // available in all modern browsers
log('randomUUID()', randUUID);

// ---------------------------------------------------------------------------
// 2. HASHING  (SHA-1, SHA-256, SHA-384, SHA-512)
// ---------------------------------------------------------------------------
console.log('\n================== HASHING (digest) ==================');

const hashAlgos = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];

for (const algo of hashAlgos) {
  await run(algo, async () => {
    const digest = await subtle.digest(algo, plainBytes);
    log(algo, toHex(digest));
  });
}

// ---------------------------------------------------------------------------
// 3. HMAC  (HMAC-SHA-1, HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512)
// ---------------------------------------------------------------------------
console.log('\n================== HMAC ==================');

for (const hash of hashAlgos) {
  await run(`HMAC-${hash}`, async () => {
    const key = await subtle.generateKey(
      { name: 'HMAC', hash },
      false,           // non-extractable for sign/verify
      ['sign', 'verify']
    );

    const sig = await subtle.sign('HMAC', key, plainBytes);
    const valid = await subtle.verify('HMAC', key, sig, plainBytes);
    log(`HMAC-${hash}`, `sig=${toHex(sig)} | verified=${valid}`);
  });
}

// ---------------------------------------------------------------------------
// 4. AES-CBC  (128, 192, 256-bit keys)
// ---------------------------------------------------------------------------
console.log('\n================== AES-CBC (encrypt / decrypt) ==================');

for (const length of [128, 192, 256]) {
  await run(`AES-CBC-${length}`, async () => {
    const iv  = crypto.getRandomValues(new Uint8Array(16));
    const key = await subtle.generateKey(
      { name: 'AES-CBC', length },
      true,
      ['encrypt', 'decrypt']
    );

    const ciphertext  = await subtle.encrypt({ name: 'AES-CBC', iv }, key, plainBytes);
    const decrypted   = await subtle.decrypt({ name: 'AES-CBC', iv }, key, ciphertext);
    const match = dec.decode(decrypted) === plainText;
    log(`AES-CBC-${length}`, `encrypted=${toHex(ciphertext)} | decrypted="${dec.decode(decrypted)}" | match=${match}`);
  });
}

// ---------------------------------------------------------------------------
// 5. AES-CTR  (128, 192, 256-bit keys)
// ---------------------------------------------------------------------------
console.log('\n================== AES-CTR (encrypt / decrypt) ==================');

for (const length of [128, 192, 256]) {
  await run(`AES-CTR-${length}`, async () => {
    const counter = crypto.getRandomValues(new Uint8Array(16));
    const key = await subtle.generateKey(
      { name: 'AES-CTR', length },
      true,
      ['encrypt', 'decrypt']
    );

    const ciphertext = await subtle.encrypt(
      { name: 'AES-CTR', counter, length: 64 },   // 64-bit counter
      key, plainBytes
    );
    const decrypted = await subtle.decrypt(
      { name: 'AES-CTR', counter, length: 64 },
      key, ciphertext
    );
    const match = dec.decode(decrypted) === plainText;
    log(`AES-CTR-${length}`, `encrypted=${toHex(ciphertext)} | decrypted="${dec.decode(decrypted)}" | match=${match}`);
  });
}

// ---------------------------------------------------------------------------
// 6. AES-GCM  (128, 192, 256-bit keys) — AEAD
// ---------------------------------------------------------------------------
console.log('\n================== AES-GCM (AEAD encrypt / decrypt) ==================');

for (const length of [128, 192, 256]) {
  await run(`AES-GCM-${length}`, async () => {
    const iv  = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV recommended
    const aad = enc.encode('additional authenticated data');
    const key = await subtle.generateKey(
      { name: 'AES-GCM', length },
      true,
      ['encrypt', 'decrypt']
    );

    // Web Crypto appends the 128-bit auth tag to the ciphertext automatically
    const ciphertext = await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
      key, plainBytes
    );
    const decrypted = await subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
      key, ciphertext
    );
    const match = dec.decode(decrypted) === plainText;
    log(`AES-GCM-${length}`, `ciphertext+tag=${toHex(ciphertext)} | decrypted="${dec.decode(decrypted)}" | match=${match}`);
  });
}

// ---------------------------------------------------------------------------
// 7. AES-KW  (AES Key Wrap — 128, 192, 256-bit wrapping keys)
// ---------------------------------------------------------------------------
console.log('\n================== AES-KW (Key Wrap / Unwrap) ==================');

for (const length of [128, 192, 256]) {
  await run(`AES-KW-${length}`, async () => {
    // Key-wrapping key (the wrapper)
    const wrappingKey = await subtle.generateKey(
      { name: 'AES-KW', length },
      false,
      ['wrapKey', 'unwrapKey']
    );

    // Key to be wrapped (an AES-GCM key as the target)
    const targetKey = await subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,            // must be extractable to be wrapped
      ['encrypt', 'decrypt']
    );

    const wrappedKey   = await subtle.wrapKey('raw', targetKey, wrappingKey, 'AES-KW');
    const unwrappedKey = await subtle.unwrapKey(
      'raw', wrappedKey, wrappingKey,
      'AES-KW',
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    // Round-trip check: export both and compare raw bytes
    const originalRaw   = await subtle.exportKey('raw', targetKey);
    const unwrappedRaw  = await subtle.exportKey('raw', unwrappedKey);
    const match = toHex(originalRaw) === toHex(unwrappedRaw);
    log(`AES-KW-${length}`, `wrappedKey=${toHex(wrappedKey)} | roundTrip=${match}`);
  });
}

// ---------------------------------------------------------------------------
// 8. RSA-OAEP  (encrypt / decrypt) — SHA-1, SHA-256, SHA-384, SHA-512
// ---------------------------------------------------------------------------
console.log('\n================== RSA-OAEP (encrypt / decrypt) ==================');

for (const hash of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
  await run(`RSA-OAEP-${hash}`, async () => {
    const { publicKey, privateKey } = await subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
        hash,
      },
      false,
      ['encrypt', 'decrypt']
    );

    const ciphertext = await subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, plainBytes);
    const decrypted  = await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, ciphertext);
    const match = dec.decode(decrypted) === plainText;
    log(`RSA-OAEP-${hash}`, `encrypted=${toHex(ciphertext)} | decrypted="${dec.decode(decrypted)}" | match=${match}`);
  });
}

// RSA-OAEP with label (optional label parameter)
await run('RSA-OAEP-SHA-256 with label', async () => {
  const { publicKey, privateKey } = await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    },
    false,
    ['encrypt', 'decrypt']
  );
  const label = enc.encode('my-oaep-label');
  const ciphertext = await subtle.encrypt({ name: 'RSA-OAEP', label }, publicKey, plainBytes);
  const decrypted  = await subtle.decrypt({ name: 'RSA-OAEP', label }, privateKey, ciphertext);
  log('RSA-OAEP-SHA-256+label', `decrypted="${dec.decode(decrypted)}" | match=${dec.decode(decrypted) === plainText}`);
});

// ---------------------------------------------------------------------------
// 9. RSASSA-PKCS1-v1_5  (sign / verify) — SHA-256, SHA-384, SHA-512
// ---------------------------------------------------------------------------
console.log('\n================== RSASSA-PKCS1-v1_5 (sign / verify) ==================');

for (const hash of ['SHA-256', 'SHA-384', 'SHA-512']) {
  await run(`RSASSA-PKCS1-v1_5-${hash}`, async () => {
    const { publicKey, privateKey } = await subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash,
      },
      false,
      ['sign', 'verify']
    );

    const signature = await subtle.sign('RSASSA-PKCS1-v1_5', privateKey, plainBytes);
    const valid     = await subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signature, plainBytes);
    log(`RSASSA-PKCS1-v1_5-${hash}`, `sig=${toHex(signature)} | verified=${valid}`);
  });
}

// ---------------------------------------------------------------------------
// 10. RSA-PSS  (sign / verify) — SHA-256, SHA-384, SHA-512
// ---------------------------------------------------------------------------
console.log('\n================== RSA-PSS (sign / verify) ==================');

for (const hash of ['SHA-256', 'SHA-384', 'SHA-512']) {
  await run(`RSA-PSS-${hash}`, async () => {
    const { publicKey, privateKey } = await subtle.generateKey(
      {
        name: 'RSA-PSS',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash,
      },
      false,
      ['sign', 'verify']
    );

    const saltLength = 32;
    const signature  = await subtle.sign({ name: 'RSA-PSS', saltLength }, privateKey, plainBytes);
    const valid      = await subtle.verify({ name: 'RSA-PSS', saltLength }, publicKey, signature, plainBytes);
    log(`RSA-PSS-${hash}`, `sig=${toHex(signature)} | verified=${valid}`);
  });
}

// ---------------------------------------------------------------------------
// 11. ECDSA  (sign / verify) — P-256, P-384, P-521
// ---------------------------------------------------------------------------
console.log('\n================== ECDSA (sign / verify) ==================');

const ecdsaCombinations = [
  { namedCurve: 'P-256', hash: 'SHA-256' },
  { namedCurve: 'P-384', hash: 'SHA-384' },
  { namedCurve: 'P-521', hash: 'SHA-512' },
];

for (const { namedCurve, hash } of ecdsaCombinations) {
  await run(`ECDSA-${namedCurve}-${hash}`, async () => {
    const { publicKey, privateKey } = await subtle.generateKey(
      { name: 'ECDSA', namedCurve },
      false,
      ['sign', 'verify']
    );

    const signature = await subtle.sign({ name: 'ECDSA', hash }, privateKey, plainBytes);
    const valid     = await subtle.verify({ name: 'ECDSA', hash }, publicKey, signature, plainBytes);
    log(`ECDSA-${namedCurve}-${hash}`, `sig=${toHex(signature)} | verified=${valid}`);
  });
}

// ---------------------------------------------------------------------------
// 12. ECDH  (key agreement) — P-256, P-384, P-521
// ---------------------------------------------------------------------------
console.log('\n================== ECDH (key agreement) ==================');

for (const namedCurve of ['P-256', 'P-384', 'P-521']) {
  await run(`ECDH-${namedCurve}`, async () => {
    const alice = await subtle.generateKey({ name: 'ECDH', namedCurve }, false, ['deriveKey', 'deriveBits']);
    const bob   = await subtle.generateKey({ name: 'ECDH', namedCurve }, false, ['deriveKey', 'deriveBits']);

    // Derive shared secret bits (256, 384 or 521 bits depending on curve)
    const bitLen = { 'P-256': 256, 'P-384': 384, 'P-521': 528 }[namedCurve];

    const aliceBits = await subtle.deriveBits(
      { name: 'ECDH', public: bob.publicKey },
      alice.privateKey, bitLen
    );
    const bobBits = await subtle.deriveBits(
      { name: 'ECDH', public: alice.publicKey },
      bob.privateKey, bitLen
    );

    const match = toHex(aliceBits) === toHex(bobBits);
    log(`ECDH-${namedCurve}`, `sharedSecret=${toHex(aliceBits)} | match=${match}`);
  });
}

// ECDH used to derive an AES-GCM key directly (deriveKey)
await run('ECDH-P-256 → AES-GCM-256 deriveKey', async () => {
  const alice = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
  const bob   = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);

  const aliceAesKey = await subtle.deriveKey(
    { name: 'ECDH', public: bob.publicKey },
    alice.privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const bobAesKey = await subtle.deriveKey(
    { name: 'ECDH', public: alice.publicKey },
    bob.privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, aliceAesKey, plainBytes);
  const decrypted  = await subtle.decrypt({ name: 'AES-GCM', iv }, bobAesKey, ciphertext);
  log('ECDH-P-256→AES-GCM-256', `decrypted="${dec.decode(decrypted)}" | match=${dec.decode(decrypted) === plainText}`);
});

// ---------------------------------------------------------------------------
// 13. PBKDF2  (key derivation from password)
// ---------------------------------------------------------------------------
console.log('\n================== PBKDF2 (key derivation) ==================');

// Import the password as a raw key material for PBKDF2
const pbkdf2Base = await subtle.importKey(
  'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']
);

for (const hash of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
  await run(`PBKDF2-${hash}`, async () => {
    const bits = await subtle.deriveBits(
      { name: 'PBKDF2', salt, hash, iterations: 100000 },
      pbkdf2Base, 256
    );
    log(`PBKDF2-${hash} (256 bits)`, toHex(bits));
  });
}

// PBKDF2 → derive an AES-GCM key and use it
await run('PBKDF2-SHA-256 → AES-GCM-256 deriveKey + encrypt', async () => {
  const aesKey = await subtle.deriveKey(
    { name: 'PBKDF2', salt, hash: 'SHA-256', iterations: 100000 },
    pbkdf2Base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plainBytes);
  const decrypted  = await subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
  log('PBKDF2→AES-GCM', `decrypted="${dec.decode(decrypted)}" | match=${dec.decode(decrypted) === plainText}`);
});

// ---------------------------------------------------------------------------
// 14. HKDF  (HMAC-based key derivation)
// ---------------------------------------------------------------------------
console.log('\n================== HKDF (key derivation) ==================');

// Import some key material (could be a shared ECDH secret in a real app)
const hkdfBase = await subtle.importKey(
  'raw', enc.encode(password), 'HKDF', false, ['deriveBits', 'deriveKey']
);

const info = enc.encode('application-context-info');

for (const hash of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
  await run(`HKDF-${hash}`, async () => {
    const bits = await subtle.deriveBits(
      { name: 'HKDF', salt, hash, info },
      hkdfBase, 256
    );
    log(`HKDF-${hash} (256 bits)`, toHex(bits));
  });
}

// HKDF → derive an AES-CBC key and use it
await run('HKDF-SHA-256 → AES-CBC-256 deriveKey + encrypt', async () => {
  const aesKey = await subtle.deriveKey(
    { name: 'HKDF', salt, hash: 'SHA-256', info },
    hkdfBase,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ciphertext = await subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, plainBytes);
  const decrypted  = await subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, ciphertext);
  log('HKDF→AES-CBC', `decrypted="${dec.decode(decrypted)}" | match=${dec.decode(decrypted) === plainText}`);
});

// ---------------------------------------------------------------------------
// 15. KEY IMPORT / EXPORT  (JWK, PKCS8, SPKI, raw)
// ---------------------------------------------------------------------------
console.log('\n================== KEY IMPORT / EXPORT ==================');

// Export / import AES-GCM key as JWK
await run('AES-GCM key export (JWK) + reimport', async () => {
  const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const jwk  = await subtle.exportKey('jwk', key);
  log('AES-GCM JWK (kty)', jwk.kty);
  log('AES-GCM JWK (alg)', jwk.alg);
  log('AES-GCM JWK (k)',   jwk.k);

  const imported = await subtle.importKey('jwk', jwk, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const reimported = await subtle.exportKey('jwk', imported);
  log('AES-GCM reimport match', reimported.k === jwk.k);
});

// Export EC key pair as SPKI (public) and PKCS8 (private)
await run('ECDSA P-256 key export (SPKI / PKCS8) + reimport', async () => {
  const { publicKey, privateKey } = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  );

  const spki  = await subtle.exportKey('spki',  publicKey);
  const pkcs8 = await subtle.exportKey('pkcs8', privateKey);
  log('ECDSA public  (SPKI hex)',  toHex(spki));
  log('ECDSA private (PKCS8 hex)', toHex(pkcs8));

  // Reimport and round-trip sign/verify
  const reimportedPub  = await subtle.importKey('spki',  spki,  { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  const reimportedPriv = await subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);

  const sig   = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, reimportedPriv, plainBytes);
  const valid = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, reimportedPub, sig, plainBytes);
  log('ECDSA SPKI/PKCS8 reimport sign+verify', `verified=${valid}`);
});

// Export RSA key pair as JWK
await run('RSA-OAEP SHA-256 key export (JWK) + reimport', async () => {
  const { publicKey, privateKey } = await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );

  const pubJwk  = await subtle.exportKey('jwk', publicKey);
  const privJwk = await subtle.exportKey('jwk', privateKey);
  log('RSA-OAEP public  JWK (kty.n length)', String(pubJwk.n?.length) + ' base64url chars');
  log('RSA-OAEP private JWK (has d)', String(privJwk.d !== undefined));

  const reimportedPub  = await subtle.importKey('jwk', pubJwk,  { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
  const reimportedPriv = await subtle.importKey('jwk', privJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
  const ciphertext = await subtle.encrypt({ name: 'RSA-OAEP' }, reimportedPub,  plainBytes);
  const decrypted  = await subtle.decrypt({ name: 'RSA-OAEP' }, reimportedPriv, ciphertext);
  log('RSA-OAEP JWK reimport encrypt+decrypt', `match=${dec.decode(decrypted) === plainText}`);
});

// Export HMAC key as raw bytes
await run('HMAC SHA-256 key export (raw) + reimport', async () => {
  const key = await subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify']);
  const raw = await subtle.exportKey('raw', key);
  log('HMAC raw key hex', toHex(raw));

  const reimported = await subtle.importKey(
    'raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
  const sig   = await subtle.sign('HMAC', reimported, plainBytes);
  const valid = await subtle.verify('HMAC', reimported, sig, plainBytes);
  log('HMAC raw reimport sign+verify', `verified=${valid}`);
});

// ---------------------------------------------------------------------------
// 16. COMBINED SCENARIO: Encrypt-then-MAC (AES-GCM + HMAC over ciphertext)
// ---------------------------------------------------------------------------
console.log('\n================== COMBINED: Encrypt-then-MAC ==================');

await run('AES-GCM-256 + HMAC-SHA-256 over ciphertext', async () => {
  const encKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const macKey = await subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, encKey, plainBytes);

  // MAC over IV + ciphertext
  const toSign = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  toSign.set(iv, 0);
  toSign.set(new Uint8Array(ciphertext), iv.byteLength);

  const mac       = await subtle.sign('HMAC', macKey, toSign);
  const macValid  = await subtle.verify('HMAC', macKey, mac, toSign);
  const decrypted = await subtle.decrypt({ name: 'AES-GCM', iv }, encKey, ciphertext);

  log('Encrypt-then-MAC', `macValid=${macValid} | decrypted="${dec.decode(decrypted)}" | match=${dec.decode(decrypted) === plainText}`);
});

// ---------------------------------------------------------------------------
// 17. COMBINED SCENARIO: ECDH key exchange → AES-GCM + HKDF
// ---------------------------------------------------------------------------
console.log('\n================== COMBINED: ECDH + HKDF + AES-GCM ==================');

await run('ECDH-P-256 → HKDF-SHA-256 → AES-GCM-256', async () => {
  // Simulate Alice and Bob performing ECDH and then using HKDF to stretch the
  // shared secret before encrypting a message with AES-GCM.
  const alice = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const bob   = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);

  const sharedBits = await subtle.deriveBits(
    { name: 'ECDH', public: bob.publicKey }, alice.privateKey, 256
  );

  // Stretch with HKDF
  const hkdfMaterial = await subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  const aesKey = await subtle.deriveKey(
    { name: 'HKDF', salt: crypto.getRandomValues(new Uint8Array(16)), hash: 'SHA-256', info: enc.encode('ecdh-aes-session') },
    hkdfMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plainBytes);
  const decrypted  = await subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
  log('ECDH+HKDF+AES-GCM', `decrypted="${dec.decode(decrypted)}" | match=${dec.decode(decrypted) === plainText}`);
});

console.log('\n================== ALL DONE ==================\n');
