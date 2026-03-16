const CryptoJS = require('crypto-js');

const plainText = 'Somebody is coding again!';
const secret = 'super-secret-key';
const passphrase = 'my-passphrase';

// ============================================================
// 1. HASHING (Message Digests)
// ============================================================
console.log('================== HASHING ==================');

// MD5
const md5 = CryptoJS.MD5(plainText).toString();
console.log(`  MD5: ${md5}`);

// SHA-1
const sha1 = CryptoJS.SHA1(plainText).toString();
console.log(`  SHA-1: ${sha1}`);

// SHA-224
const sha224 = CryptoJS.SHA224(plainText).toString();
console.log(`  SHA-224: ${sha224}`);

// SHA-256
const sha256 = CryptoJS.SHA256(plainText).toString();
console.log(`  SHA-256: ${sha256}`);

// SHA-384
const sha384 = CryptoJS.SHA384(plainText).toString();
console.log(`  SHA-384: ${sha384}`);

// SHA-512
const sha512 = CryptoJS.SHA512(plainText).toString();
console.log(`  SHA-512: ${sha512}`);

// SHA-3 (default 512-bit)
const sha3_512 = CryptoJS.SHA3(plainText).toString();
console.log(`  SHA-3 (512): ${sha3_512}`);

// SHA-3 (256-bit)
const sha3_256 = CryptoJS.SHA3(plainText, { outputLength: 256 }).toString();
console.log(`  SHA-3 (256): ${sha3_256}`);

// SHA-3 (384-bit)
const sha3_384 = CryptoJS.SHA3(plainText, { outputLength: 384 }).toString();
console.log(`  SHA-3 (384): ${sha3_384}`);

// SHA-3 (224-bit)
const sha3_224 = CryptoJS.SHA3(plainText, { outputLength: 224 }).toString();
console.log(`  SHA-3 (224): ${sha3_224}`);

// RIPEMD-160
const ripemd160 = CryptoJS.RIPEMD160(plainText).toString();
console.log(`  RIPEMD-160: ${ripemd160}`);

// ============================================================
// 2. HMAC (Hash-based Message Authentication Code)
// ============================================================
console.log('\n================== HMAC ==================');

// HMAC-MD5
const hmacMd5 = CryptoJS.HmacMD5(plainText, secret).toString();
console.log(`  HMAC-MD5: ${hmacMd5}`);

// HMAC-SHA1
const hmacSha1 = CryptoJS.HmacSHA1(plainText, secret).toString();
console.log(`  HMAC-SHA1: ${hmacSha1}`);

// HMAC-SHA224
const hmacSha224 = CryptoJS.HmacSHA224(plainText, secret).toString();
console.log(`  HMAC-SHA224: ${hmacSha224}`);

// HMAC-SHA256
const hmacSha256 = CryptoJS.HmacSHA256(plainText, secret).toString();
console.log(`  HMAC-SHA256: ${hmacSha256}`);

// HMAC-SHA384
const hmacSha384 = CryptoJS.HmacSHA384(plainText, secret).toString();
console.log(`  HMAC-SHA384: ${hmacSha384}`);

// HMAC-SHA512
const hmacSha512 = CryptoJS.HmacSHA512(plainText, secret).toString();
console.log(`  HMAC-SHA512: ${hmacSha512}`);

// HMAC-SHA3
const hmacSha3 = CryptoJS.HmacSHA3(plainText, secret).toString();
console.log(`  HMAC-SHA3: ${hmacSha3}`);

// HMAC-RIPEMD160
const hmacRipemd160 = CryptoJS.HmacRIPEMD160(plainText, secret).toString();
console.log(`  HMAC-RIPEMD160: ${hmacRipemd160}`);

// ============================================================
// 3. PBKDF2 (Password-Based Key Derivation)
// ============================================================
console.log('\n================== PBKDF2 ==================');

const salt = CryptoJS.lib.WordArray.random(128 / 8);

// PBKDF2 with default (SHA-1)
const pbkdf2Default = CryptoJS.PBKDF2(passphrase, salt, {
  keySize: 256 / 32,
  iterations: 1000,
}).toString();
console.log(`  PBKDF2 (SHA-1, 1000 iter): ${pbkdf2Default}`);

// PBKDF2 with SHA-256
const pbkdf2Sha256 = CryptoJS.PBKDF2(passphrase, salt, {
  keySize: 256 / 32,
  iterations: 1000,
  hasher: CryptoJS.algo.SHA256,
}).toString();
console.log(`  PBKDF2 (SHA-256, 1000 iter): ${pbkdf2Sha256}`);

// PBKDF2 with SHA-512
const pbkdf2Sha512 = CryptoJS.PBKDF2(passphrase, salt, {
  keySize: 512 / 32,
  iterations: 1000,
  hasher: CryptoJS.algo.SHA512,
}).toString();
console.log(`  PBKDF2 (SHA-512, 1000 iter): ${pbkdf2Sha512}`);

// PBKDF2 with SHA-384
const pbkdf2Sha384 = CryptoJS.PBKDF2(passphrase, salt, {
  keySize: 384 / 32,
  iterations: 1000,
  hasher: CryptoJS.algo.SHA384,
}).toString();
console.log(`  PBKDF2 (SHA-384, 1000 iter): ${pbkdf2Sha384}`);

// PBKDF2 with MD5
const pbkdf2Md5 = CryptoJS.PBKDF2(passphrase, salt, {
  keySize: 128 / 32,
  iterations: 1000,
  hasher: CryptoJS.algo.MD5,
}).toString();
console.log(`  PBKDF2 (MD5, 1000 iter): ${pbkdf2Md5}`);

// ============================================================
// 4. SYMMETRIC CIPHERS – Passphrase-based (PBE)
// ============================================================
console.log('\n================== SYMMETRIC CIPHERS (passphrase) ==================');

// --- AES ---
try {
  const encrypted = CryptoJS.AES.encrypt(plainText, passphrase).toString();
  const decrypted = CryptoJS.AES.decrypt(encrypted, passphrase).toString(CryptoJS.enc.Utf8);
  console.log(`  AES (passphrase): encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  AES (passphrase): [ERROR] ${err.message}`);
}

// --- DES ---
try {
  const encrypted = CryptoJS.DES.encrypt(plainText, passphrase).toString();
  const decrypted = CryptoJS.DES.decrypt(encrypted, passphrase).toString(CryptoJS.enc.Utf8);
  console.log(`  DES (passphrase): encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  DES (passphrase): [ERROR] ${err.message}`);
}

// --- TripleDES ---
try {
  const encrypted = CryptoJS.TripleDES.encrypt(plainText, passphrase).toString();
  const decrypted = CryptoJS.TripleDES.decrypt(encrypted, passphrase).toString(CryptoJS.enc.Utf8);
  console.log(`  TripleDES (passphrase): encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  TripleDES (passphrase): [ERROR] ${err.message}`);
}

// --- Rabbit ---
try {
  const encrypted = CryptoJS.Rabbit.encrypt(plainText, passphrase).toString();
  const decrypted = CryptoJS.Rabbit.decrypt(encrypted, passphrase).toString(CryptoJS.enc.Utf8);
  console.log(`  Rabbit (passphrase): encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  Rabbit (passphrase): [ERROR] ${err.message}`);
}

// --- RC4 ---
try {
  const encrypted = CryptoJS.RC4.encrypt(plainText, passphrase).toString();
  const decrypted = CryptoJS.RC4.decrypt(encrypted, passphrase).toString(CryptoJS.enc.Utf8);
  console.log(`  RC4 (passphrase): encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  RC4 (passphrase): [ERROR] ${err.message}`);
}

// --- RC4Drop ---
try {
  const encrypted = CryptoJS.RC4Drop.encrypt(plainText, passphrase).toString();
  const decrypted = CryptoJS.RC4Drop.decrypt(encrypted, passphrase).toString(CryptoJS.enc.Utf8);
  console.log(`  RC4Drop (passphrase): encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  RC4Drop (passphrase): [ERROR] ${err.message}`);
}

// --- Blowfish ---
try {
  const encrypted = CryptoJS.Blowfish.encrypt(plainText, passphrase).toString();
  const decrypted = CryptoJS.Blowfish.decrypt(encrypted, passphrase).toString(CryptoJS.enc.Utf8);
  console.log(`  Blowfish (passphrase): encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  Blowfish (passphrase): [ERROR] ${err.message}`);
}

// ============================================================
// 5. SYMMETRIC CIPHERS – Explicit Key & IV
// ============================================================
console.log('\n================== SYMMETRIC CIPHERS (explicit key/iv) ==================');

const key128 = CryptoJS.lib.WordArray.random(128 / 8);
const key192 = CryptoJS.lib.WordArray.random(192 / 8);
const key256 = CryptoJS.lib.WordArray.random(256 / 8);
const iv128 = CryptoJS.lib.WordArray.random(128 / 8);
const iv64 = CryptoJS.lib.WordArray.random(64 / 8);

// --- AES-CBC (128-bit key) ---
try {
  const encrypted = CryptoJS.AES.encrypt(plainText, key128, { iv: iv128, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  const decrypted = CryptoJS.AES.decrypt(encrypted.toString(), key128, { iv: iv128, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
  console.log(`  AES-128-CBC: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  AES-128-CBC: [ERROR] ${err.message}`);
}

// --- AES-CBC (256-bit key) ---
try {
  const encrypted = CryptoJS.AES.encrypt(plainText, key256, { iv: iv128, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  const decrypted = CryptoJS.AES.decrypt(encrypted.toString(), key256, { iv: iv128, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
  console.log(`  AES-256-CBC: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  AES-256-CBC: [ERROR] ${err.message}`);
}

// --- AES-CFB ---
try {
  const encrypted = CryptoJS.AES.encrypt(plainText, key256, { iv: iv128, mode: CryptoJS.mode.CFB, padding: CryptoJS.pad.Pkcs7 });
  const decrypted = CryptoJS.AES.decrypt(encrypted.toString(), key256, { iv: iv128, mode: CryptoJS.mode.CFB, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
  console.log(`  AES-256-CFB: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  AES-256-CFB: [ERROR] ${err.message}`);
}

// --- AES-CTR ---
try {
  const encrypted = CryptoJS.AES.encrypt(plainText, key256, { iv: iv128, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding });
  const decrypted = CryptoJS.AES.decrypt(encrypted.toString(), key256, { iv: iv128, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding }).toString(CryptoJS.enc.Utf8);
  console.log(`  AES-256-CTR: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  AES-256-CTR: [ERROR] ${err.message}`);
}

// --- AES-OFB ---
try {
  const encrypted = CryptoJS.AES.encrypt(plainText, key256, { iv: iv128, mode: CryptoJS.mode.OFB, padding: CryptoJS.pad.NoPadding });
  const decrypted = CryptoJS.AES.decrypt(encrypted.toString(), key256, { iv: iv128, mode: CryptoJS.mode.OFB, padding: CryptoJS.pad.NoPadding }).toString(CryptoJS.enc.Utf8);
  console.log(`  AES-256-OFB: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  AES-256-OFB: [ERROR] ${err.message}`);
}

// --- AES-ECB ---
try {
  const encrypted = CryptoJS.AES.encrypt(plainText, key256, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
  const decrypted = CryptoJS.AES.decrypt(encrypted.toString(), key256, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
  console.log(`  AES-256-ECB: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  AES-256-ECB: [ERROR] ${err.message}`);
}

// --- DES-CBC (explicit key) ---
try {
  const desKey = CryptoJS.lib.WordArray.random(64 / 8);
  const encrypted = CryptoJS.DES.encrypt(plainText, desKey, { iv: iv64, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  const decrypted = CryptoJS.DES.decrypt(encrypted.toString(), desKey, { iv: iv64, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
  console.log(`  DES-CBC: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  DES-CBC: [ERROR] ${err.message}`);
}

// --- DES-ECB ---
try {
  const desKey = CryptoJS.lib.WordArray.random(64 / 8);
  const encrypted = CryptoJS.DES.encrypt(plainText, desKey, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
  const decrypted = CryptoJS.DES.decrypt(encrypted.toString(), desKey, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
  console.log(`  DES-ECB: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  DES-ECB: [ERROR] ${err.message}`);
}

// --- TripleDES-CBC (explicit key) ---
try {
  const encrypted = CryptoJS.TripleDES.encrypt(plainText, key192, { iv: iv64, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  const decrypted = CryptoJS.TripleDES.decrypt(encrypted.toString(), key192, { iv: iv64, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
  console.log(`  TripleDES-CBC: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  TripleDES-CBC: [ERROR] ${err.message}`);
}

// --- TripleDES-ECB ---
try {
  const encrypted = CryptoJS.TripleDES.encrypt(plainText, key192, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
  const decrypted = CryptoJS.TripleDES.decrypt(encrypted.toString(), key192, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
  console.log(`  TripleDES-ECB: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  TripleDES-ECB: [ERROR] ${err.message}`);
}

// --- Rabbit (explicit key) ---
try {
  const rabbitKey = CryptoJS.lib.WordArray.random(128 / 8);
  const rabbitIv = CryptoJS.lib.WordArray.random(64 / 8);
  const encrypted = CryptoJS.Rabbit.encrypt(plainText, rabbitKey, { iv: rabbitIv });
  const decrypted = CryptoJS.Rabbit.decrypt(encrypted.toString(), rabbitKey, { iv: rabbitIv }).toString(CryptoJS.enc.Utf8);
  console.log(`  Rabbit: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  Rabbit: [ERROR] ${err.message}`);
}

// --- RC4 (explicit key) ---
try {
  const rc4Key = CryptoJS.lib.WordArray.random(128 / 8);
  const encrypted = CryptoJS.RC4.encrypt(plainText, rc4Key);
  const decrypted = CryptoJS.RC4.decrypt(encrypted.toString(), rc4Key).toString(CryptoJS.enc.Utf8);
  console.log(`  RC4: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  RC4: [ERROR] ${err.message}`);
}

// --- RC4Drop (explicit key) ---
try {
  const rc4DropKey = CryptoJS.lib.WordArray.random(128 / 8);
  const encrypted = CryptoJS.RC4Drop.encrypt(plainText, rc4DropKey, { drop: 768 });
  const decrypted = CryptoJS.RC4Drop.decrypt(encrypted.toString(), rc4DropKey, { drop: 768 }).toString(CryptoJS.enc.Utf8);
  console.log(`  RC4Drop (drop=768): encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  RC4Drop: [ERROR] ${err.message}`);
}

// --- Blowfish-CBC (explicit key) ---
try {
  const bfKey = CryptoJS.lib.WordArray.random(128 / 8);
  const encrypted = CryptoJS.Blowfish.encrypt(plainText, bfKey, { iv: iv64, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  const decrypted = CryptoJS.Blowfish.decrypt(encrypted.toString(), bfKey, { iv: iv64, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
  console.log(`  Blowfish-CBC: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  Blowfish-CBC: [ERROR] ${err.message}`);
}

// --- Blowfish-ECB ---
try {
  const bfKey = CryptoJS.lib.WordArray.random(128 / 8);
  const encrypted = CryptoJS.Blowfish.encrypt(plainText, bfKey, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
  const decrypted = CryptoJS.Blowfish.decrypt(encrypted.toString(), bfKey, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
  console.log(`  Blowfish-ECB: encrypted=${encrypted} | decrypted="${decrypted}" | match=${decrypted === plainText}`);
} catch (err) {
  console.log(`  Blowfish-ECB: [ERROR] ${err.message}`);
}

// ============================================================
// 6. PADDING SCHEMES
// ============================================================
console.log('\n================== PADDING SCHEMES ==================');

const paddings = {
  'Pkcs7': CryptoJS.pad.Pkcs7,
  'Iso97971': CryptoJS.pad.Iso97971,
  'AnsiX923': CryptoJS.pad.AnsiX923,
  'ZeroPadding': CryptoJS.pad.ZeroPadding,
  'NoPadding': CryptoJS.pad.NoPadding,
};

Object.entries(paddings).forEach(([padName, padScheme]) => {
  try {
    const encrypted = CryptoJS.AES.encrypt(plainText, key256, { iv: iv128, mode: CryptoJS.mode.CBC, padding: padScheme });
    const decrypted = CryptoJS.AES.decrypt(encrypted.toString(), key256, { iv: iv128, mode: CryptoJS.mode.CBC, padding: padScheme }).toString(CryptoJS.enc.Utf8);
    const matches = padName === 'NoPadding' ? 'N/A (stream)' : (decrypted === plainText);
    console.log(`  AES-CBC + ${padName}: encrypted=${encrypted} | decrypted="${decrypted}" | match=${matches}`);
  } catch (err) {
    console.log(`  AES-CBC + ${padName}: [ERROR] ${err.message}`);
  }
});

// ============================================================
// 7. ENCODING FORMATS
// ============================================================
console.log('\n================== ENCODING FORMATS ==================');

const wordArray = CryptoJS.SHA256(plainText);

// Hex
console.log(`  Hex: ${wordArray.toString(CryptoJS.enc.Hex)}`);

// Base64
console.log(`  Base64: ${wordArray.toString(CryptoJS.enc.Base64)}`);

// Base64url
console.log(`  Base64url: ${wordArray.toString(CryptoJS.enc.Base64url)}`);

// Latin1
console.log(`  Latin1 length: ${wordArray.toString(CryptoJS.enc.Latin1).length}`);

// Utf8 parse/stringify round-trip
const utf8Parsed = CryptoJS.enc.Utf8.parse(plainText);
const utf8Back = CryptoJS.enc.Utf8.stringify(utf8Parsed);
console.log(`  Utf8 round-trip: "${utf8Back}" | match=${utf8Back === plainText}`);

// Hex parse/stringify round-trip
const hexStr = CryptoJS.enc.Hex.stringify(utf8Parsed);
const hexParsed = CryptoJS.enc.Hex.parse(hexStr);
const hexBack = CryptoJS.enc.Utf8.stringify(hexParsed);
console.log(`  Hex round-trip: "${hexBack}" | match=${hexBack === plainText}`);

// Base64 parse/stringify round-trip
const b64Str = CryptoJS.enc.Base64.stringify(utf8Parsed);
const b64Parsed = CryptoJS.enc.Base64.parse(b64Str);
const b64Back = CryptoJS.enc.Utf8.stringify(b64Parsed);
console.log(`  Base64 round-trip: "${b64Back}" | match=${b64Back === plainText}`);

// ============================================================
// 8. CIPHER OUTPUT FORMATS (OpenSSL vs custom)
// ============================================================
console.log('\n================== CIPHER FORMATS ==================');

// OpenSSL format (default)
const opensslEncrypted = CryptoJS.AES.encrypt(plainText, passphrase, {
  format: CryptoJS.format.OpenSSL,
});
const opensslDecrypted = CryptoJS.AES.decrypt(opensslEncrypted.toString(), passphrase, {
  format: CryptoJS.format.OpenSSL,
}).toString(CryptoJS.enc.Utf8);
console.log(`  OpenSSL format: encrypted=${opensslEncrypted} | decrypted="${opensslDecrypted}" | match=${opensslDecrypted === plainText}`);

// Custom JSON formatter
const JsonFormatter = {
  stringify: function (cipherParams) {
    const jsonObj = { ct: cipherParams.ciphertext.toString(CryptoJS.enc.Base64) };
    if (cipherParams.iv) jsonObj.iv = cipherParams.iv.toString();
    if (cipherParams.salt) jsonObj.s = cipherParams.salt.toString();
    return JSON.stringify(jsonObj);
  },
  parse: function (jsonStr) {
    const jsonObj = JSON.parse(jsonStr);
    const cipherParams = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Base64.parse(jsonObj.ct),
    });
    if (jsonObj.iv) cipherParams.iv = CryptoJS.enc.Hex.parse(jsonObj.iv);
    if (jsonObj.s) cipherParams.salt = CryptoJS.enc.Hex.parse(jsonObj.s);
    return cipherParams;
  },
};

const jsonEncrypted = CryptoJS.AES.encrypt(plainText, passphrase, { format: JsonFormatter });
const jsonDecrypted = CryptoJS.AES.decrypt(jsonEncrypted.toString(), passphrase, { format: JsonFormatter }).toString(CryptoJS.enc.Utf8);
console.log(`  JSON format: encrypted=${jsonEncrypted} | decrypted="${jsonDecrypted}" | match=${jsonDecrypted === plainText}`);

// ============================================================
// 9. PROGRESSIVE HASHING (streaming / incremental)
// ============================================================
console.log('\n================== PROGRESSIVE HASHING ==================');

// Progressive SHA-256
const sha256Hasher = CryptoJS.algo.SHA256.create();
sha256Hasher.update('Somebody ');
sha256Hasher.update('is coding ');
sha256Hasher.update('again!');
const progressiveSha256 = sha256Hasher.finalize().toString();
console.log(`  Progressive SHA-256: ${progressiveSha256}`);
console.log(`  Matches one-shot:    ${progressiveSha256 === sha256}`);

// Progressive HMAC-SHA256
const hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, secret);
hmacHasher.update('Somebody ');
hmacHasher.update('is coding ');
hmacHasher.update('again!');
const progressiveHmac = hmacHasher.finalize().toString();
console.log(`  Progressive HMAC-SHA256: ${progressiveHmac}`);
console.log(`  Matches one-shot:       ${progressiveHmac === hmacSha256}`);

// ============================================================
// 10. PROGRESSIVE ENCRYPTION (streaming / incremental)
// ============================================================
console.log('\n================== PROGRESSIVE ENCRYPTION ==================');

try {
  const progKey = CryptoJS.lib.WordArray.random(256 / 8);
  const progIv = CryptoJS.lib.WordArray.random(128 / 8);

  // Progressive encrypt
  const aesEncryptor = CryptoJS.algo.AES.createEncryptor(progKey, { iv: progIv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  let ciphertext = aesEncryptor.process('Somebody ');
  ciphertext.concat(aesEncryptor.process('is coding '));
  ciphertext.concat(aesEncryptor.process('again!'));
  ciphertext.concat(aesEncryptor.finalize());
  console.log(`  Progressive AES encrypt: ${ciphertext.toString(CryptoJS.enc.Hex)}`);

  // Progressive decrypt
  const aesDecryptor = CryptoJS.algo.AES.createDecryptor(progKey, { iv: progIv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  let decryptedWords = aesDecryptor.process(ciphertext);
  decryptedWords.concat(aesDecryptor.finalize());
  const progressiveDecrypted = decryptedWords.toString(CryptoJS.enc.Utf8);
  console.log(`  Progressive AES decrypt: "${progressiveDecrypted}"`);
} catch (err) {
  console.log(`  Progressive AES: [ERROR] ${err.message}`);
}

// ============================================================
// 11. EvpKDF (OpenSSL-compatible KDF)
// ============================================================
console.log('\n================== EvpKDF ==================');

const evpKey = CryptoJS.EvpKDF(passphrase, salt, {
  keySize: 256 / 32,
  iterations: 1000,
  hasher: CryptoJS.algo.SHA256,
}).toString();
console.log(`  EvpKDF (SHA-256): ${evpKey}`);

const evpKeyMd5 = CryptoJS.EvpKDF(passphrase, salt, {
  keySize: 256 / 32,
  iterations: 1,
  hasher: CryptoJS.algo.MD5,
}).toString();
console.log(`  EvpKDF (MD5, default iter): ${evpKeyMd5}`);

// ============================================================
// 12. WordArray utilities
// ============================================================
console.log('\n================== WordArray Utilities ==================');

// Random WordArray
const randomWords = CryptoJS.lib.WordArray.random(32);
console.log(`  Random (32 bytes): ${randomWords.toString()}`);

// Create from string
const fromString = CryptoJS.enc.Utf8.parse('hello world');
console.log(`  From string: ${fromString.toString(CryptoJS.enc.Hex)}`);

// Concatenation
const part1 = CryptoJS.enc.Hex.parse('aabbccdd');
const part2 = CryptoJS.enc.Hex.parse('eeff0011');
part1.concat(part2);
console.log(`  Concatenated: ${part1.toString(CryptoJS.enc.Hex)}`);

// Clamp (truncate to sigBytes)
const clamped = CryptoJS.lib.WordArray.random(16);
clamped.sigBytes = 8;
clamped.clamp();
console.log(`  Clamped (8 bytes from 16): ${clamped.toString(CryptoJS.enc.Hex)} (length: ${clamped.toString(CryptoJS.enc.Hex).length / 2} bytes)`);

// ============================================================
// 13. ALL CIPHERS × ALL MODES MATRIX
// ============================================================
console.log('\n================== CIPHER × MODE MATRIX ==================');

const cipherAlgos = {
  'AES': { algo: CryptoJS.AES, keySize: 256, ivSize: 128 },
  'DES': { algo: CryptoJS.DES, keySize: 64, ivSize: 64 },
  'TripleDES': { algo: CryptoJS.TripleDES, keySize: 192, ivSize: 64 },
  'Blowfish': { algo: CryptoJS.Blowfish, keySize: 128, ivSize: 64 },
};

const modes = {
  'CBC': CryptoJS.mode.CBC,
  'CFB': CryptoJS.mode.CFB,
  'CTR': CryptoJS.mode.CTR,
  'OFB': CryptoJS.mode.OFB,
  'ECB': CryptoJS.mode.ECB,
};

Object.entries(cipherAlgos).forEach(([cipherName, { algo, keySize, ivSize }]) => {
  Object.entries(modes).forEach(([modeName, modeObj]) => {
    try {
      const k = CryptoJS.lib.WordArray.random(keySize / 8);
      const iv = modeName !== 'ECB' ? CryptoJS.lib.WordArray.random(ivSize / 8) : undefined;
      const opts = { mode: modeObj, padding: CryptoJS.pad.Pkcs7 };
      if (iv) opts.iv = iv;

      const encrypted = algo.encrypt(plainText, k, opts);
      const decrypted = algo.decrypt(encrypted.toString(), k, opts).toString(CryptoJS.enc.Utf8);
      console.log(`  ${cipherName}-${modeName}: match=${decrypted === plainText}`);
    } catch (err) {
      console.log(`  ${cipherName}-${modeName}: [ERROR] ${err.message}`);
    }
  });
});

// Stream ciphers (no mode/IV needed for matrix)
['Rabbit', 'RC4', 'RC4Drop'].forEach(name => {
  try {
    const streamKey = CryptoJS.lib.WordArray.random(128 / 8);
    const encrypted = CryptoJS[name].encrypt(plainText, streamKey);
    const decrypted = CryptoJS[name].decrypt(encrypted.toString(), streamKey).toString(CryptoJS.enc.Utf8);
    console.log(`  ${name} (stream): match=${decrypted === plainText}`);
  } catch (err) {
    console.log(`  ${name} (stream): [ERROR] ${err.message}`);
  }
});

console.log('\n================== DONE ==================');
