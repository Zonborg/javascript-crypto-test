const crypto = require("crypto");

const plainText = "Somebody is coding again!"
const hash = crypto.createHash("md5").update(plainText).digest("hex");
const hash2 = crypto.createHash("sha1").update(plainText).digest("hex");
const hash3 = crypto.createHash("sha224").update(plainText).digest("hex");
const hash4 = crypto.createHash("sha256").update(plainText).digest("hex");
const hash5 = crypto.createHash("sha384").update(plainText).digest("hex");
const hash6 = crypto.createHash("sha512").update(plainText).digest("hex");
const hash7 = crypto.createHash("sha3-256").update(plainText).digest("hex");


console.log("Plain text is: "+ plainText + " MD5 Value is: "+ hash);
console.log("Plain text is: "+ plainText + " SHA1 Value is: "+ hash2);
console.log("Plain text is: "+ plainText + " SHA-224 Value is: "+ hash3);
console.log("Plain text is: "+ plainText + " SHA-256 Value is: "+ hash4);
console.log("Plain text is: "+ plainText + " SHA-384 Value is: "+ hash5);
console.log("Plain text is: "+ plainText + " SHA-512 Value is: "+ hash6);
