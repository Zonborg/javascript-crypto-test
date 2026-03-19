// webcrypto-shim polyfills the Web Crypto API for older browsers.
// In Node.js, crypto.webcrypto provides the same API natively.
// Require the shim so CodeQL can detect its usage.
require('webcrypto-shim');

const { webcrypto } = require('crypto');
const subtle = webcrypto.subtle;

const plainText = 'Somebody is coding again!';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const data = encoder.encode(plainText);

// Helper: convert ArrayBuffer to hex string
function bufToHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper: convert ArrayBuffer to Base64
function bufToBase64(buf) {
  return Buffer.from(buf).toString('base64');
}

(async () => {

// ============================================================
// 1. HASHING (digest)
// ============================================================
console.log('================== HASHING ==================');

const hashAlgos = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
for (const algo of hashAlgos) {
  const digest = await subtle.digest(algo, data);
  console.log(`  ${algo}: ${bufToHex(digest)}`);
}

// ============================================================
// 2. HMAC (sign + verify)
// ============================================================
console.log('\n================== HMAC ==================');

for (const hash of hashAlgos) {
  const hmacKey = await subtle.generateKey(
    { name: 'HMAC', hash: { name: hash } },
    true,
    ['sign', 'verify']
  );
  const signature = await subtle.sign('HMAC', hmacKey, data);
  const valid = await subtle.verify('HMAC', hmacKey, signature, data);
  console.log(`  HMAC-${hash}: sig=${bufToHex(signature).slice(0, 32)}... | verified=${valid}`);

  // Export/import round-trip
  const rawKey = await subtle.exportKey('raw', hmacKey);
  const importedKey = await subtle.importKey('raw', rawKey, { name: 'HMAC', hash }, false, ['verify']);
  const valid2 = await subtle.verify('HMAC', importedKey, signature, data);
  console.log(`  HMAC-${hash} import round-trip: verified=${valid2}`);
}

// ============================================================
// 3. AES-CBC (encrypt + decrypt)
// ============================================================
console.log('\n================== AES-CBC ==================');

for (const keyLen of [128, 192, 256]) {
  const key = await subtle.generateKey(
    { name: 'AES-CBC', length: keyLen },
    true,
    ['encrypt', 'decrypt']
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const encrypted = await subtle.encrypt({ name: 'AES-CBC', iv }, key, data);
  const decrypted = await subtle.decrypt({ name: 'AES-CBC', iv }, key, encrypted);
  const result = decoder.decode(decrypted);
  console.log(`  AES-CBC-${keyLen}: encrypted=${bufToHex(encrypted).slice(0, 32)}... | decrypted="${result}" | match=${result === plainText}`);

  // Export as raw, re-import
  const rawKey = await subtle.exportKey('raw', key);
  const imported = await subtle.importKey('raw', rawKey, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
  const enc2 = await subtle.encrypt({ name: 'AES-CBC', iv }, imported, data);
  const dec2 = await subtle.decrypt({ name: 'AES-CBC', iv }, imported, enc2);
  console.log(`  AES-CBC-${keyLen} import round-trip: match=${decoder.decode(dec2) === plainText}`);
}

// ============================================================
// 4. AES-CTR (encrypt + decrypt)
// ============================================================
console.log('\n================== AES-CTR ==================');

for (const keyLen of [128, 192, 256]) {
  const key = await subtle.generateKey(
    { name: 'AES-CTR', length: keyLen },
    true,
    ['encrypt', 'decrypt']
  );
  const counter = webcrypto.getRandomValues(new Uint8Array(16));
  const encrypted = await subtle.encrypt({ name: 'AES-CTR', counter, length: 64 }, key, data);
  const decrypted = await subtle.decrypt({ name: 'AES-CTR', counter, length: 64 }, key, encrypted);
  const result = decoder.decode(decrypted);
  console.log(`  AES-CTR-${keyLen}: encrypted=${bufToHex(encrypted).slice(0, 32)}... | decrypted="${result}" | match=${result === plainText}`);
}

// ============================================================
// 5. AES-GCM (encrypt + decrypt, AEAD)
// ============================================================
console.log('\n================== AES-GCM ==================');

for (const keyLen of [128, 192, 256]) {
  const key = await subtle.generateKey(
    { name: 'AES-GCM', length: keyLen },
    true,
    ['encrypt', 'decrypt']
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const aad = encoder.encode('additional authenticated data');

  // Without AAD
  const encrypted = await subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  const decrypted = await subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
  const result = decoder.decode(decrypted);
  console.log(`  AES-GCM-${keyLen}: encrypted=${bufToHex(encrypted).slice(0, 32)}... | decrypted="${result}" | match=${result === plainText}`);

  // With AAD
  const encWithAAD = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, data);
  const decWithAAD = await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, encWithAAD);
  console.log(`  AES-GCM-${keyLen} (AAD): match=${decoder.decode(decWithAAD) === plainText}`);

  // With custom tag length
  for (const tagLength of [96, 104, 112, 120, 128]) {
    const iv2 = webcrypto.getRandomValues(new Uint8Array(12));
    const encTag = await subtle.encrypt({ name: 'AES-GCM', iv: iv2, tagLength }, key, data);
    const decTag = await subtle.decrypt({ name: 'AES-GCM', iv: iv2, tagLength }, key, encTag);
    console.log(`  AES-GCM-${keyLen} (tag=${tagLength}): match=${decoder.decode(decTag) === plainText}`);
  }
}

// ============================================================
// 6. AES-KW (key wrapping)
// ============================================================
console.log('\n================== AES-KW ==================');

for (const keyLen of [128, 192, 256]) {
  const wrappingKey = await subtle.generateKey(
    { name: 'AES-KW', length: keyLen },
    true,
    ['wrapKey', 'unwrapKey']
  );
  // Wrap an AES key
  const keyToWrap = await subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const wrapped = await subtle.wrapKey('raw', keyToWrap, wrappingKey, 'AES-KW');
  const unwrapped = await subtle.unwrapKey(
    'raw', wrapped, wrappingKey, 'AES-KW',
    { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
  );
  const rawOrig = await subtle.exportKey('raw', keyToWrap);
  const rawUnwrapped = await subtle.exportKey('raw', unwrapped);
  console.log(`  AES-KW-${keyLen}: wrapped=${bufToHex(wrapped).slice(0, 32)}... | keys match=${bufToHex(rawOrig) === bufToHex(rawUnwrapped)}`);
}

// ============================================================
// 7. RSA-OAEP (encrypt + decrypt)
// ============================================================
console.log('\n================== RSA-OAEP ==================');

for (const hash of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
  const rsaKeyPair = await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: hash },
    },
    true,
    ['encrypt', 'decrypt']
  );
  const encrypted = await subtle.encrypt({ name: 'RSA-OAEP' }, rsaKeyPair.publicKey, data);
  const decrypted = await subtle.decrypt({ name: 'RSA-OAEP' }, rsaKeyPair.privateKey, encrypted);
  const result = decoder.decode(decrypted);
  console.log(`  RSA-OAEP (${hash}): encrypted=${bufToHex(encrypted).slice(0, 32)}... | decrypted="${result}" | match=${result === plainText}`);

  // With optional label
  const label = encoder.encode('my-label');
  const encLabeled = await subtle.encrypt({ name: 'RSA-OAEP', label }, rsaKeyPair.publicKey, data);
  const decLabeled = await subtle.decrypt({ name: 'RSA-OAEP', label }, rsaKeyPair.privateKey, encLabeled);
  console.log(`  RSA-OAEP (${hash}, labeled): match=${decoder.decode(decLabeled) === plainText}`);

  // Export/import key pair
  const pubJwk = await subtle.exportKey('jwk', rsaKeyPair.publicKey);
  const privJwk = await subtle.exportKey('jwk', rsaKeyPair.privateKey);
  const importedPub = await subtle.importKey('jwk', pubJwk, { name: 'RSA-OAEP', hash }, false, ['encrypt']);
  const importedPriv = await subtle.importKey('jwk', privJwk, { name: 'RSA-OAEP', hash }, false, ['decrypt']);
  const enc3 = await subtle.encrypt({ name: 'RSA-OAEP' }, importedPub, data);
  const dec3 = await subtle.decrypt({ name: 'RSA-OAEP' }, importedPriv, enc3);
  console.log(`  RSA-OAEP (${hash}) JWK round-trip: match=${decoder.decode(dec3) === plainText}`);
}

// ============================================================
// 8. RSASSA-PKCS1-v1_5 (sign + verify)
// ============================================================
console.log('\n================== RSASSA-PKCS1-v1_5 ==================');

for (const hash of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
  const keyPair = await subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: hash },
    },
    true,
    ['sign', 'verify']
  );
  const signature = await subtle.sign('RSASSA-PKCS1-v1_5', keyPair.privateKey, data);
  const valid = await subtle.verify('RSASSA-PKCS1-v1_5', keyPair.publicKey, signature, data);
  console.log(`  RSASSA-PKCS1-v1_5 (${hash}): sig=${bufToHex(signature).slice(0, 32)}... | verified=${valid}`);

  // Export as SPKI/PKCS8 and re-import
  const spki = await subtle.exportKey('spki', keyPair.publicKey);
  const pkcs8 = await subtle.exportKey('pkcs8', keyPair.privateKey);
  const importedPub = await subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
  const importedPriv = await subtle.importKey('pkcs8', pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['sign']);
  const sig2 = await subtle.sign('RSASSA-PKCS1-v1_5', importedPriv, data);
  const valid2 = await subtle.verify('RSASSA-PKCS1-v1_5', importedPub, sig2, data);
  console.log(`  RSASSA-PKCS1-v1_5 (${hash}) SPKI/PKCS8 round-trip: verified=${valid2}`);
}

// ============================================================
// 9. RSA-PSS (sign + verify)
// ============================================================
console.log('\n================== RSA-PSS ==================');

for (const hash of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
  const keyPair = await subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: hash },
    },
    true,
    ['sign', 'verify']
  );

  for (const saltLength of [0, 16, 32]) {
    const signature = await subtle.sign({ name: 'RSA-PSS', saltLength }, keyPair.privateKey, data);
    const valid = await subtle.verify({ name: 'RSA-PSS', saltLength }, keyPair.publicKey, signature, data);
    console.log(`  RSA-PSS (${hash}, salt=${saltLength}): sig=${bufToHex(signature).slice(0, 32)}... | verified=${valid}`);
  }
}

// ============================================================
// 10. ECDSA (sign + verify)
// ============================================================
console.log('\n================== ECDSA ==================');

for (const namedCurve of ['P-256', 'P-384', 'P-521']) {
  const keyPair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve },
    true,
    ['sign', 'verify']
  );

  for (const hash of ['SHA-256', 'SHA-384', 'SHA-512']) {
    const signature = await subtle.sign({ name: 'ECDSA', hash: { name: hash } }, keyPair.privateKey, data);
    const valid = await subtle.verify({ name: 'ECDSA', hash: { name: hash } }, keyPair.publicKey, signature, data);
    console.log(`  ECDSA (${namedCurve}, ${hash}): sig=${bufToHex(signature).slice(0, 32)}... | verified=${valid}`);
  }

  // Export/import JWK round-trip
  const pubJwk = await subtle.exportKey('jwk', keyPair.publicKey);
  const privJwk = await subtle.exportKey('jwk', keyPair.privateKey);
  const importedPub = await subtle.importKey('jwk', pubJwk, { name: 'ECDSA', namedCurve }, false, ['verify']);
  const importedPriv = await subtle.importKey('jwk', privJwk, { name: 'ECDSA', namedCurve }, false, ['sign']);
  const sig2 = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, importedPriv, data);
  const valid2 = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, importedPub, sig2, data);
  console.log(`  ECDSA (${namedCurve}) JWK round-trip: verified=${valid2}`);

  // Export as SPKI/PKCS8
  const spki = await subtle.exportKey('spki', keyPair.publicKey);
  const pkcs8 = await subtle.exportKey('pkcs8', keyPair.privateKey);
  console.log(`  ECDSA (${namedCurve}) SPKI: ${bufToHex(spki).slice(0, 32)}...`);
  console.log(`  ECDSA (${namedCurve}) PKCS8: ${bufToHex(pkcs8).slice(0, 32)}...`);
}

// ============================================================
// 11. ECDH (key derivation / key agreement)
// ============================================================
console.log('\n================== ECDH ==================');

for (const namedCurve of ['P-256', 'P-384', 'P-521']) {
  const aliceKeyPair = await subtle.generateKey(
    { name: 'ECDH', namedCurve },
    true,
    ['deriveBits', 'deriveKey']
  );
  const bobKeyPair = await subtle.generateKey(
    { name: 'ECDH', namedCurve },
    true,
    ['deriveBits', 'deriveKey']
  );

  // deriveBits
  const aliceBits = await subtle.deriveBits(
    { name: 'ECDH', public: bobKeyPair.publicKey },
    aliceKeyPair.privateKey,
    256
  );
  const bobBits = await subtle.deriveBits(
    { name: 'ECDH', public: aliceKeyPair.publicKey },
    bobKeyPair.privateKey,
    256
  );
  console.log(`  ECDH (${namedCurve}) deriveBits: shared secrets match=${bufToHex(aliceBits) === bufToHex(bobBits)}`);

  // deriveKey (derive an AES key from ECDH)
  const derivedKey = await subtle.deriveKey(
    { name: 'ECDH', public: bobKeyPair.publicKey },
    aliceKeyPair.privateKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const enc = await subtle.encrypt({ name: 'AES-GCM', iv }, derivedKey, data);
  const derivedKey2 = await subtle.deriveKey(
    { name: 'ECDH', public: aliceKeyPair.publicKey },
    bobKeyPair.privateKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const dec = await subtle.decrypt({ name: 'AES-GCM', iv }, derivedKey2, enc);
  console.log(`  ECDH (${namedCurve}) deriveKey+AES-GCM: match=${decoder.decode(dec) === plainText}`);
}

// ============================================================
// 12. PBKDF2 (password-based key derivation)
// ============================================================
console.log('\n================== PBKDF2 ==================');

const passwordData = encoder.encode('my-password');
const pbkdf2BaseKey = await subtle.importKey('raw', passwordData, 'PBKDF2', false, ['deriveBits', 'deriveKey']);

for (const hash of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
  for (const iterations of [1000, 100000]) {
    const salt = webcrypto.getRandomValues(new Uint8Array(16));
    const derivedBits = await subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations, hash },
      pbkdf2BaseKey,
      256
    );
    console.log(`  PBKDF2 (${hash}, ${iterations} iter): ${bufToHex(derivedBits)}`);
  }

  // deriveKey: derive AES key from password
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const aesKey = await subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash },
    pbkdf2BaseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const enc = await subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, data);
  const dec = await subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, enc);
  console.log(`  PBKDF2 (${hash}) deriveKey+AES-GCM: match=${decoder.decode(dec) === plainText}`);
}

// ============================================================
// 13. HKDF (HMAC-based Key Derivation Function)
// ============================================================
console.log('\n================== HKDF ==================');

const hkdfKeyMaterial = await subtle.importKey('raw', encoder.encode('input-key-material'), 'HKDF', false, ['deriveBits', 'deriveKey']);

for (const hash of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const info = encoder.encode('application-specific-info');

  const derivedBits = await subtle.deriveBits(
    { name: 'HKDF', hash, salt, info },
    hkdfKeyMaterial,
    256
  );
  console.log(`  HKDF (${hash}): ${bufToHex(derivedBits)}`);

  // deriveKey
  const aesKey = await subtle.deriveKey(
    { name: 'HKDF', hash, salt, info },
    hkdfKeyMaterial,
    { name: 'AES-CBC', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const enc = await subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, data);
  const dec = await subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, enc);
  console.log(`  HKDF (${hash}) deriveKey+AES-CBC: match=${decoder.decode(dec) === plainText}`);
}

// ============================================================
// 14. KEY WRAPPING with RSA-OAEP
// ============================================================
console.log('\n================== KEY WRAPPING (RSA-OAEP) ==================');

const wrapKeyPair = await subtle.generateKey(
  {
    name: 'RSA-OAEP',
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  },
  true,
  ['wrapKey', 'unwrapKey']
);

// Wrap an AES key with RSA-OAEP
const aesKeyToWrap = await subtle.generateKey(
  { name: 'AES-GCM', length: 256 },
  true,
  ['encrypt', 'decrypt']
);
const wrappedRsa = await subtle.wrapKey('raw', aesKeyToWrap, wrapKeyPair.publicKey, 'RSA-OAEP');
const unwrappedRsa = await subtle.unwrapKey(
  'raw', wrappedRsa, wrapKeyPair.privateKey, 'RSA-OAEP',
  { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
);
const origRaw = await subtle.exportKey('raw', aesKeyToWrap);
const unwrappedRaw = await subtle.exportKey('raw', unwrappedRsa);
console.log(`  RSA-OAEP wrap/unwrap: keys match=${bufToHex(origRaw) === bufToHex(unwrappedRaw)}`);

// Wrap with AES-GCM
const aesWrapKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey']);
const wrapIv = webcrypto.getRandomValues(new Uint8Array(12));
const wrappedGcm = await subtle.wrapKey('raw', aesKeyToWrap, aesWrapKey, { name: 'AES-GCM', iv: wrapIv });
const unwrappedGcm = await subtle.unwrapKey(
  'raw', wrappedGcm, aesWrapKey, { name: 'AES-GCM', iv: wrapIv },
  { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
);
const unwrappedGcmRaw = await subtle.exportKey('raw', unwrappedGcm);
console.log(`  AES-GCM wrap/unwrap: keys match=${bufToHex(origRaw) === bufToHex(unwrappedGcmRaw)}`);

// ============================================================
// 15. KEY FORMAT ROUND-TRIPS
// ============================================================
console.log('\n================== KEY FORMAT ROUND-TRIPS ==================');

// Raw AES key
const rawAesKey = await subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']);
const rawExport = await subtle.exportKey('raw', rawAesKey);
const rawImport = await subtle.importKey('raw', rawExport, { name: 'AES-CBC' }, true, ['encrypt', 'decrypt']);
const rawExport2 = await subtle.exportKey('raw', rawImport);
console.log(`  AES raw round-trip: match=${bufToHex(rawExport) === bufToHex(rawExport2)}`);

// JWK AES key
const jwkExport = await subtle.exportKey('jwk', rawAesKey);
const jwkImport = await subtle.importKey('jwk', jwkExport, { name: 'AES-CBC' }, true, ['encrypt', 'decrypt']);
const jwkExport2 = await subtle.exportKey('jwk', jwkImport);
console.log(`  AES JWK round-trip: match=${jwkExport.k === jwkExport2.k}`);

// RSA key formats
const rsaKey = await subtle.generateKey(
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true,
  ['sign', 'verify']
);

// SPKI (public)
const spkiExport = await subtle.exportKey('spki', rsaKey.publicKey);
const spkiImport = await subtle.importKey('spki', spkiExport, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']);
const spkiExport2 = await subtle.exportKey('spki', spkiImport);
console.log(`  RSA SPKI round-trip: match=${bufToHex(spkiExport) === bufToHex(spkiExport2)}`);

// PKCS8 (private)
const pkcs8Export = await subtle.exportKey('pkcs8', rsaKey.privateKey);
const pkcs8Import = await subtle.importKey('pkcs8', pkcs8Export, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['sign']);
const pkcs8Export2 = await subtle.exportKey('pkcs8', pkcs8Import);
console.log(`  RSA PKCS8 round-trip: match=${bufToHex(pkcs8Export) === bufToHex(pkcs8Export2)}`);

// JWK (RSA public)
const rsaJwk = await subtle.exportKey('jwk', rsaKey.publicKey);
const rsaJwkImport = await subtle.importKey('jwk', rsaJwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']);
const rsaJwk2 = await subtle.exportKey('jwk', rsaJwkImport);
console.log(`  RSA JWK round-trip: match=${rsaJwk.n === rsaJwk2.n && rsaJwk.e === rsaJwk2.e}`);

// EC key formats
const ecKey = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);

const ecSpki = await subtle.exportKey('spki', ecKey.publicKey);
const ecSpkiImport = await subtle.importKey('spki', ecSpki, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
const ecSpki2 = await subtle.exportKey('spki', ecSpkiImport);
console.log(`  EC SPKI round-trip: match=${bufToHex(ecSpki) === bufToHex(ecSpki2)}`);

const ecPkcs8 = await subtle.exportKey('pkcs8', ecKey.privateKey);
const ecPkcs8Import = await subtle.importKey('pkcs8', ecPkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
const ecPkcs82 = await subtle.exportKey('pkcs8', ecPkcs8Import);
console.log(`  EC PKCS8 round-trip: match=${bufToHex(ecPkcs8) === bufToHex(ecPkcs82)}`);

const ecJwk = await subtle.exportKey('jwk', ecKey.publicKey);
const ecJwkImport = await subtle.importKey('jwk', ecJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
const ecJwk2 = await subtle.exportKey('jwk', ecJwkImport);
console.log(`  EC JWK round-trip: match=${ecJwk.x === ecJwk2.x && ecJwk.y === ecJwk2.y}`);

// ============================================================
// 16. RANDOM NUMBER GENERATION
// ============================================================
console.log('\n================== RANDOM NUMBER GENERATION ==================');

const randomBytes16 = webcrypto.getRandomValues(new Uint8Array(16));
console.log(`  getRandomValues (16 bytes): ${bufToHex(randomBytes16.buffer)}`);

const randomBytes32 = webcrypto.getRandomValues(new Uint8Array(32));
console.log(`  getRandomValues (32 bytes): ${bufToHex(randomBytes32.buffer)}`);

const randomInt32 = webcrypto.getRandomValues(new Int32Array(4));
console.log(`  getRandomValues (Int32Array): [${randomInt32.join(', ')}]`);

const randomUuid = webcrypto.randomUUID();
console.log(`  randomUUID: ${randomUuid}`);

// ============================================================
// 17. CROSS-ALGORITHM KEY DERIVATION CHAINS
// ============================================================
console.log('\n================== KEY DERIVATION CHAINS ==================');

// Password -> PBKDF2 -> AES-GCM key -> encrypt -> ECDH -> derive new AES key
const chainPassword = encoder.encode('chain-password');
const chainBaseKey = await subtle.importKey('raw', chainPassword, 'PBKDF2', false, ['deriveKey']);
const chainSalt = webcrypto.getRandomValues(new Uint8Array(16));

const chainAesKey = await subtle.deriveKey(
  { name: 'PBKDF2', salt: chainSalt, iterations: 100000, hash: 'SHA-256' },
  chainBaseKey,
  { name: 'AES-GCM', length: 256 },
  false,
  ['encrypt', 'decrypt']
);
const chainIv = webcrypto.getRandomValues(new Uint8Array(12));
const chainEncrypted = await subtle.encrypt({ name: 'AES-GCM', iv: chainIv }, chainAesKey, data);
const chainDecrypted = await subtle.decrypt({ name: 'AES-GCM', iv: chainIv }, chainAesKey, chainEncrypted);
console.log(`  PBKDF2 -> AES-GCM: match=${decoder.decode(chainDecrypted) === plainText}`);

// HKDF -> AES-CBC key -> encrypt
const hkdfMaterial = await subtle.importKey('raw', encoder.encode('hkdf-material'), 'HKDF', false, ['deriveKey']);
const hkdfDerivedKey = await subtle.deriveKey(
  { name: 'HKDF', hash: 'SHA-512', salt: webcrypto.getRandomValues(new Uint8Array(32)), info: encoder.encode('chain-info') },
  hkdfMaterial,
  { name: 'AES-CBC', length: 256 },
  false,
  ['encrypt', 'decrypt']
);
const hkdfIv = webcrypto.getRandomValues(new Uint8Array(16));
const hkdfEnc = await subtle.encrypt({ name: 'AES-CBC', iv: hkdfIv }, hkdfDerivedKey, data);
const hkdfDec = await subtle.decrypt({ name: 'AES-CBC', iv: hkdfIv }, hkdfDerivedKey, hkdfEnc);
console.log(`  HKDF -> AES-CBC: match=${decoder.decode(hkdfDec) === plainText}`);

console.log('\n================== DONE ==================');

})().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
