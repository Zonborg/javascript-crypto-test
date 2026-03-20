const crypto = require('crypto');

const plainText = 'Somebody is coding again!';
const secret = 'super-secret-key';
const password = 'password';
const salt = crypto.randomBytes(16);

// ============================================================
// 1. HASHING (Message Digests)
// ============================================================
console.log('================== HASHING ==================');

const hashAlgorithms = crypto.getHashes();
console.log(`Available hash algorithms (${hashAlgorithms.length}):`, hashAlgorithms.join(', '));
console.log();

hashAlgorithms.forEach(algo => {
  try {
    const hash = crypto.createHash(algo).update(plainText).digest('hex');
    console.log(`  ${algo}: ${hash}`);
  } catch (err) {
    console.log(`  ${algo}: [ERROR] ${err.message}`);
  }
});

// ============================================================
// 2. HMAC (Hash-based Message Authentication Code)
// ============================================================
console.log('\n================== HMAC ==================');

hashAlgorithms.forEach(algo => {
  try {
    const hmac = crypto.createHmac(algo, secret).update(plainText).digest('hex');
    console.log(`  ${algo}: ${hmac}`);
  } catch (err) {
    console.log(`  ${algo}: [ERROR] ${err.message}`);
  }
});

// ============================================================
// 3. SYMMETRIC CIPHERS (encrypt + decrypt)
// ============================================================
console.log('\n================== SYMMETRIC CIPHERS ==================');

const ciphers = crypto.getCiphers();
console.log(`Available ciphers (${ciphers.length}):`, ciphers.join(', '));
console.log();

// Key/IV sizes for common cipher families
const cipherConfigs = [
  // AES-CBC
  { name: 'aes-128-cbc', keyLen: 16, ivLen: 16 },
  { name: 'aes-192-cbc', keyLen: 24, ivLen: 16 },
  { name: 'aes-256-cbc', keyLen: 32, ivLen: 16 },
  // AES-CTR
  { name: 'aes-128-ctr', keyLen: 16, ivLen: 16 },
  { name: 'aes-192-ctr', keyLen: 24, ivLen: 16 },
  { name: 'aes-256-ctr', keyLen: 32, ivLen: 16 },
  // AES-CFB
  { name: 'aes-128-cfb', keyLen: 16, ivLen: 16 },
  { name: 'aes-256-cfb', keyLen: 32, ivLen: 16 },
  // AES-OFB
  { name: 'aes-128-ofb', keyLen: 16, ivLen: 16 },
  { name: 'aes-256-ofb', keyLen: 32, ivLen: 16 },
  // AES-ECB (no IV)
  { name: 'aes-128-ecb', keyLen: 16, ivLen: 0 },
  { name: 'aes-256-ecb', keyLen: 32, ivLen: 0 },
  // DES / 3DES
  { name: 'des-cbc', keyLen: 8, ivLen: 8 },
  { name: 'des-ede3-cbc', keyLen: 24, ivLen: 8 },
  { name: 'des-ede3', keyLen: 24, ivLen: 0 },
  // Camellia
  { name: 'camellia-128-cbc', keyLen: 16, ivLen: 16 },
  { name: 'camellia-256-cbc', keyLen: 32, ivLen: 16 },
  // ARIA
  { name: 'aria-128-cbc', keyLen: 16, ivLen: 16 },
  { name: 'aria-256-cbc', keyLen: 32, ivLen: 16 },
  // SM4
  { name: 'sm4-cbc', keyLen: 16, ivLen: 16 },
  // ChaCha20
  { name: 'chacha20', keyLen: 32, ivLen: 16 },
  // RC4 (stream cipher, no IV)
  { name: 'rc4', keyLen: 16, ivLen: 0 },
  // BF (Blowfish)
  { name: 'bf-cbc', keyLen: 16, ivLen: 8 },
  // CAST5
  { name: 'cast5-cbc', keyLen: 16, ivLen: 8 },
  // SEED
  { name: 'seed-cbc', keyLen: 16, ivLen: 16 },
];

cipherConfigs.forEach(({ name, keyLen, ivLen }) => {
  try {
    const key = crypto.randomBytes(keyLen);
    const iv = ivLen > 0 ? crypto.randomBytes(ivLen) : null;
    const cipher = crypto.createCipheriv(name, key, iv);
    let encrypted = cipher.update(plainText, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const decipher = crypto.createDecipheriv(name, key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    console.log(`  ${name}: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
  } catch (err) {
    console.log(`  ${name}: [ERROR] ${err.message}`);
  }
});

// ============================================================
// 4. AEAD CIPHERS (AES-GCM, AES-CCM, ChaCha20-Poly1305)
// ============================================================
console.log('\n================== AEAD CIPHERS ==================');

// AES-128-GCM
try {
  const key = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from('additional authenticated data');
  const cipher = crypto.createCipheriv('aes-128-gcm', key, iv);
  cipher.setAAD(aad);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  const decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  console.log(`  aes-128-gcm: encrypted=${encrypted} | authTag=${authTag.toString('hex')} | decrypted="${decrypted}"`);
} catch (err) {
  console.log(`  aes-128-gcm: [ERROR] ${err.message}`);
}

// AES-256-GCM
try {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from('additional authenticated data');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  console.log(`  aes-256-gcm: encrypted=${encrypted} | authTag=${authTag.toString('hex')} | decrypted="${decrypted}"`);
} catch (err) {
  console.log(`  aes-256-gcm: [ERROR] ${err.message}`);
}

// AES-128-CCM
try {
  const key = crypto.randomBytes(16);
  const nonce = crypto.randomBytes(12);
  const aad = Buffer.from('additional authenticated data');
  const cipher = crypto.createCipheriv('aes-128-ccm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: Buffer.byteLength(plainText) });
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  const decipher = crypto.createDecipheriv('aes-128-ccm', key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad, { plaintextLength: Buffer.byteLength(plainText) });
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  console.log(`  aes-128-ccm: encrypted=${encrypted} | authTag=${authTag.toString('hex')} | decrypted="${decrypted}"`);
} catch (err) {
  console.log(`  aes-128-ccm: [ERROR] ${err.message}`);
}

// AES-256-CCM
try {
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  const aad = Buffer.from('additional authenticated data');
  const cipher = crypto.createCipheriv('aes-256-ccm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: Buffer.byteLength(plainText) });
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  const decipher = crypto.createDecipheriv('aes-256-ccm', key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad, { plaintextLength: Buffer.byteLength(plainText) });
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  console.log(`  aes-256-ccm: encrypted=${encrypted} | authTag=${authTag.toString('hex')} | decrypted="${decrypted}"`);
} catch (err) {
  console.log(`  aes-256-ccm: [ERROR] ${err.message}`);
}

// ChaCha20-Poly1305
try {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from('additional authenticated data');
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv, { authTagLength: 16 });
  cipher.setAAD(aad);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, iv, { authTagLength: 16 });
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  console.log(`  chacha20-poly1305: encrypted=${encrypted} | authTag=${authTag.toString('hex')} | decrypted="${decrypted}"`);
} catch (err) {
  console.log(`  chacha20-poly1305: [ERROR] ${err.message}`);
}

// ============================================================
// 5. KEY DERIVATION FUNCTIONS
// ============================================================
console.log('\n================== KEY DERIVATION ==================');

// PBKDF2 with various digests
const pbkdf2Digests = ['sha1', 'sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-512', null];
console.log('  --- PBKDF2 ---');
pbkdf2Digests.forEach(digest => {
  try {
    const derived = crypto.pbkdf2Sync(password, salt, 100000, 64, digest);
    console.log(`  pbkdf2-${digest}: ${derived.toString('hex')}`);
  } catch (err) {
    console.log(`  pbkdf2-${digest}: [ERROR] ${err.message}`);
  }
});

// Scrypt
console.log('  --- Scrypt ---');
try {
  const derived = crypto.scryptSync(password, salt, 64);
  console.log(`  scrypt: ${derived.toString('hex')}`);
} catch (err) {
  console.log(`  scrypt: [ERROR] ${err.message}`);
}

// HKDF
console.log('  --- HKDF ---');
try {
  crypto.hkdf('sha256', password, salt, 'info', 64, (err, derivedKey) => {
    if (err) {
      console.log(`  hkdf-sha256: [ERROR] ${err.message}`);
    } else {
      console.log(`  hkdf-sha256: ${Buffer.from(derivedKey).toString('hex')}`);
    }
  });
} catch (err) {
  console.log(`  hkdf-sha256: [ERROR] ${err.message}`);
}

try {
  const derived = crypto.hkdfSync('sha512', password, salt, 'info', 64);
  console.log(`  hkdfSync-sha512: ${Buffer.from(derived).toString('hex')}`);
} catch (err) {
  console.log(`  hkdfSync-sha512: [ERROR] ${err.message}`);
}

// ============================================================
// 6. RSA KEY PAIR GENERATION, ENCRYPTION & SIGNING
// ============================================================
console.log('\n================== RSA ==================');

const { publicKey: rsaPub, privateKey: rsaPriv } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

// RSA-OAEP encryption/decryption
try {
  const encrypted = crypto.publicEncrypt(
    { key: rsaPub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(plainText)
  );
  const decrypted = crypto.privateDecrypt(
    { key: rsaPriv, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    encrypted
  );
  console.log(`  RSA-OAEP encrypt: ${encrypted.toString('hex').substring(0, 64)}...`);
  console.log(`  RSA-OAEP decrypt: "${decrypted.toString()}" | match=${decrypted.toString() === plainText}`);
} catch (err) {
  console.log(`  RSA-OAEP: [ERROR] ${err.message}`);
}

// RSA PKCS1 v1.5 encryption/decryption
try {
  const encrypted = crypto.publicEncrypt(
    { key: rsaPub, padding: crypto.constants.RSA_PKCS1_PADDING },
    Buffer.from(plainText)
  );
  const decrypted = crypto.privateDecrypt(
    { key: rsaPriv, padding: crypto.constants.RSA_PKCS1_PADDING },
    encrypted
  );
  console.log(`  RSA-PKCS1v15 encrypt: ${encrypted.toString('hex').substring(0, 64)}...`);
  console.log(`  RSA-PKCS1v15 decrypt: "${decrypted.toString()}" | match=${decrypted.toString() === plainText}`);
} catch (err) {
  console.log(`  RSA-PKCS1v15: [ERROR] ${err.message}`);
}

// RSA Signing (PKCS1 v1.5)
const rsaSignDigests = ['SHA256', 'SHA384', 'SHA512'];
rsaSignDigests.forEach(digest => {
  try {
    const sign = crypto.createSign(digest);
    sign.update(plainText);
    const signature = sign.sign(rsaPriv, 'hex');

    const verify = crypto.createVerify(digest);
    verify.update(plainText);
    const isValid = verify.verify(rsaPub, signature, 'hex');
    console.log(`  RSA Sign ${digest}: sig=${signature.substring(0, 64)}... | verified=${isValid}`);
  } catch (err) {
    console.log(`  RSA Sign ${digest}: [ERROR] ${err.message}`);
  }
});

// RSA-PSS Signing
try {
  const { publicKey: rsaPssPub, privateKey: rsaPssPriv } = crypto.generateKeyPairSync('rsa-pss', {
    modulusLength: 2048,
    hashAlgorithm: 'SHA-256',
    mgf1HashAlgorithm: 'SHA-256',
    saltLength: 32,
  });
  const sign = crypto.createSign('SHA256');
  sign.update(plainText);
  const signature = sign.sign({ key: rsaPssPriv, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, 'hex');

  const verify = crypto.createVerify('SHA256');
  verify.update(plainText);
  const isValid = verify.verify({ key: rsaPssPub, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature, 'hex');
  console.log(`  RSA-PSS Sign SHA256: sig=${signature.substring(0, 64)}... | verified=${isValid}`);
} catch (err) {
  console.log(`  RSA-PSS: [ERROR] ${err.message}`);
}

// ============================================================
// 7. ELLIPTIC CURVE KEY PAIRS & SIGNING (ECDSA)
// ============================================================
console.log('\n================== ECDSA ==================');

const ecCurves = ['prime256v1', 'secp256k1', 'secp384r1', 'secp521r1'];
ecCurves.forEach(curve => {
  try {
    const { publicKey: ecPub, privateKey: ecPriv } = crypto.generateKeyPairSync('ec', { namedCurve: curve });

    const sign = crypto.createSign('SHA256');
    sign.update(plainText);
    const signature = sign.sign(ecPriv, 'hex');

    const verify = crypto.createVerify('SHA256');
    verify.update(plainText);
    const isValid = verify.verify(ecPub, signature, 'hex');
    console.log(`  ECDSA ${curve}: sig=${signature.substring(0, 64)}... | verified=${isValid}`);
  } catch (err) {
    console.log(`  ECDSA ${curve}: [ERROR] ${err.message}`);
  }
});

// ============================================================
// 8. Ed25519 / Ed448 SIGNING
// ============================================================
console.log('\n================== EdDSA ==================');

['ed25519', 'ed448'].forEach(type => {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync(type);
    const signature = crypto.sign(null, Buffer.from(plainText), privateKey);
    const isValid = crypto.verify(null, Buffer.from(plainText), publicKey, signature);
    console.log(`  ${type}: sig=${signature.toString('hex').substring(0, 64)}... | verified=${isValid}`);
  } catch (err) {
    console.log(`  ${type}: [ERROR] ${err.message}`);
  }
});

// ============================================================
// 9. DIFFIE-HELLMAN KEY EXCHANGE (classic DH)
// ============================================================
console.log('\n================== DIFFIE-HELLMAN ==================');

try {
  const alice = crypto.createDiffieHellman(2048);
  alice.generateKeys();
  const bob = crypto.createDiffieHellman(alice.getPrime(), alice.getGenerator());
  bob.generateKeys();

  const aliceSecret = alice.computeSecret(bob.getPublicKey());
  const bobSecret = bob.computeSecret(alice.getPublicKey());
  console.log(`  DH Alice secret: ${aliceSecret.toString('hex').substring(0, 64)}...`);
  console.log(`  DH Bob secret:   ${bobSecret.toString('hex').substring(0, 64)}...`);
  console.log(`  DH secrets match: ${aliceSecret.equals(bobSecret)}`);
} catch (err) {
  console.log(`  DH: [ERROR] ${err.message}`);
}

// ============================================================
// 10. ECDH (Elliptic Curve Diffie-Hellman)
// ============================================================
console.log('\n================== ECDH ==================');

const ecdhCurves = ['prime256v1', 'secp384r1', 'secp521r1', 'secp256k1'];
ecdhCurves.forEach(curve => {
  try {
    const alice = crypto.createECDH(curve);
    alice.generateKeys();
    const bob = crypto.createECDH(curve);
    bob.generateKeys();

    const aliceSecret = alice.computeSecret(bob.getPublicKey());
    const bobSecret = bob.computeSecret(alice.getPublicKey());
    console.log(`  ECDH ${curve}: match=${aliceSecret.equals(bobSecret)} | secret=${aliceSecret.toString('hex').substring(0, 64)}...`);
  } catch (err) {
    console.log(`  ECDH ${curve}: [ERROR] ${err.message}`);
  }
});

// ============================================================
// 11. X25519 / X448 KEY EXCHANGE
// ============================================================
console.log('\n================== X25519 / X448 KEY EXCHANGE ==================');

['x25519', 'x448'].forEach(type => {
  try {
    const alice = crypto.generateKeyPairSync(type);
    const bob = crypto.generateKeyPairSync(type);
    const aliceSecret = crypto.diffieHellman({ privateKey: alice.privateKey, publicKey: bob.publicKey });
    const bobSecret = crypto.diffieHellman({ privateKey: bob.privateKey, publicKey: alice.publicKey });
    console.log(`  ${type}: match=${aliceSecret.equals(bobSecret)} | secret=${aliceSecret.toString('hex')}`);
  } catch (err) {
    console.log(`  ${type}: [ERROR] ${err.message}`);
  }
});

// ============================================================
// 12. RANDOM NUMBER GENERATION
// ============================================================
console.log('\n================== RANDOM GENERATION ==================');

console.log(`  randomBytes(32): ${crypto.randomBytes(32).toString('hex')}`);
console.log(`  randomInt(1, 100): ${crypto.randomInt(1, 100)}`);
console.log(`  randomUUID(): ${crypto.randomUUID()}`);

try {
  const buf = Buffer.alloc(16);
  crypto.randomFillSync(buf);
  console.log(`  randomFillSync(16): ${buf.toString('hex')}`);
} catch (err) {
  console.log(`  randomFillSync: [ERROR] ${err.message}`);
}

// ============================================================
// 13. CERTIFICATE / X509 PARSING
// ============================================================
console.log('\n================== X509 CERTIFICATE ==================');

try {
  // Generate a self-signed cert for demonstration
  const { publicKey: certPub, privateKey: certPriv } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  console.log(`  Key pair generated for X509 demo (RSA 2048). X509Certificate class available: ${typeof crypto.X509Certificate === 'function'}`);
} catch (err) {
  console.log(`  X509: [ERROR] ${err.message}`);
}

// ============================================================
// 14. SECURE COMPARE (Timing-safe comparison)
// ============================================================
console.log('\n================== TIMING-SAFE EQUAL ==================');

try {
  const a = Buffer.from('hello world');
  const b = Buffer.from('hello world');
  const c = Buffer.from('hello worlD');
  console.log(`  timingSafeEqual("hello world", "hello world"): ${crypto.timingSafeEqual(a, b)}`);
  console.log(`  timingSafeEqual("hello world", "hello worlD"): ${crypto.timingSafeEqual(a, c)}`);
} catch (err) {
  console.log(`  timingSafeEqual: [ERROR] ${err.message}`);
}

// ============================================================
// 15. DSA KEY PAIR & SIGNING
// ============================================================
console.log('\n================== DSA ==================');

try {
  const { publicKey: dsaPub, privateKey: dsaPriv } = crypto.generateKeyPairSync('dsa', {
    modulusLength: 2048,
    divisorLength: 256,
  });
  const sign = crypto.createSign('SHA256');
  sign.update(plainText);
  const signature = sign.sign(dsaPriv, 'hex');

  const verify = crypto.createVerify('SHA256');
  verify.update(plainText);
  const isValid = verify.verify(dsaPub, signature, 'hex');
  console.log(`  DSA SHA256: sig=${signature.substring(0, 64)}... | verified=${isValid}`);
} catch (err) {
  console.log(`  DSA: [ERROR] ${err.message}`);
}

// ============================================================
// 16. DH NAMED GROUPS (RFC groups)
// ============================================================
console.log('\n================== DH NAMED GROUPS ==================');

try {
  const alice = crypto.createDiffieHellmanGroup('modp14');
  alice.generateKeys();
  const bob = crypto.createDiffieHellmanGroup('modp14');
  bob.generateKeys();

  const aliceSecret = alice.computeSecret(bob.getPublicKey());
  const bobSecret = bob.computeSecret(alice.getPublicKey());
  console.log(`  DH modp14: match=${aliceSecret.equals(bobSecret)} | secret=${aliceSecret.toString('hex').substring(0, 64)}...`);
} catch (err) {
  console.log(`  DH modp14: [ERROR] ${err.message}`);
}

// ============================================================
// 17. AVAILABLE CURVES LIST
// ============================================================
console.log('\n================== AVAILABLE CURVES ==================');
const curves = crypto.getCurves();
console.log(`  Curves (${curves.length}):`, curves.join(', '));

// ============================================================
// 18. crypto.sign / crypto.verify (one-shot API)
// ============================================================
console.log('\n================== ONE-SHOT sign/verify ==================');

try {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const sig = crypto.sign('sha256', Buffer.from(plainText), privateKey);
  const valid = crypto.verify('sha256', Buffer.from(plainText), publicKey, sig);
  console.log(`  One-shot EC sign/verify: sig=${sig.toString('hex').substring(0, 64)}... | verified=${valid}`);
} catch (err) {
  console.log(`  One-shot sign/verify: [ERROR] ${err.message}`);
}

// ============================================================
// 19. KEY OBJECT API (createSecretKey, createPublicKey, createPrivateKey)
// ============================================================
console.log('\n================== KEY OBJECTS ==================');

try {
  const secretKeyObj = crypto.createSecretKey(crypto.randomBytes(32));
  console.log(`  SecretKey type: ${secretKeyObj.type} | symmetricKeySize: ${secretKeyObj.symmetricKeySize}`);

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pubKeyObj = crypto.createPublicKey(publicKey);
  const privKeyObj = crypto.createPrivateKey(privateKey);
  console.log(`  PublicKey type: ${pubKeyObj.type} | asymmetricKeyType: ${pubKeyObj.asymmetricKeyType}`);
  console.log(`  PrivateKey type: ${privKeyObj.type} | asymmetricKeyType: ${privKeyObj.asymmetricKeyType}`);

  // Export in various formats
  const pubPem = pubKeyObj.export({ type: 'spki', format: 'pem' });
  const pubDer = pubKeyObj.export({ type: 'spki', format: 'der' });
  const privPem = privKeyObj.export({ type: 'pkcs8', format: 'pem' });
  console.log(`  Public key PEM length: ${pubPem.length}, DER length: ${pubDer.length}`);
  console.log(`  Private key PEM length: ${privPem.length}`);
} catch (err) {
  console.log(`  KeyObject: [ERROR] ${err.message}`);
}

// ============================================================
// 20. WEBCRYPTO API (globalThis.crypto / crypto.webcrypto)
// ============================================================
console.log('\n================== WEBCRYPTO ==================');

try {
  const wc = crypto.webcrypto || globalThis.crypto;
  if (wc && wc.subtle) {
    console.log(`  WebCrypto available: true`);
    // Demonstrate subtle.digest
    wc.subtle.digest('SHA-256', new TextEncoder().encode(plainText)).then(hash => {
      const hex = Buffer.from(hash).toString('hex');
      console.log(`  WebCrypto SHA-256: ${hex}`);
    });
  } else {
    console.log(`  WebCrypto available: false`);
  }
} catch (err) {
  console.log(`  WebCrypto: [ERROR] ${err.message}`);
}

// ============================================================
// 21. FIPS MODE CHECK
// ============================================================
console.log('\n================== FIPS ==================');
console.log(`  FIPS mode enabled: ${crypto.getFips()}`);

// ============================================================
// SUMMARY
// ============================================================
console.log('\n================== SUMMARY ==================');
console.log(`  Hash algorithms: ${hashAlgorithms.length}`);
console.log(`  Cipher algorithms: ${ciphers.length}`);
console.log(`  EC Curves: ${curves.length}`);
console.log(`  Node.js version: ${process.version}`);
console.log(`  OpenSSL version: ${process.versions.openssl}`);
