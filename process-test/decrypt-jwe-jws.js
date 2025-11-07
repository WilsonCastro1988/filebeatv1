#!/usr/bin/env node
// decrypt-jwe-jws.js
// Descifra el flujo OUT generado por el método Java encrypt()
// Uso: node decrypt-jwe-jws.js ./tmp_signcrypt/response_out.json ./certs/private.pem

const fs = require('fs');
const crypto = require('crypto');

function b64urlDecode(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) input += '=';
  return Buffer.from(input, 'base64');
}

function b64urlToString(input) {
  return b64urlDecode(input).toString('utf8');
}

if (process.argv.length < 4) {
  console.error('Uso: node decrypt-jwe-jws.js <response_json> <private_key_pem>');
  process.exit(1);
}

const respPath = process.argv[2];
const privKeyPath = process.argv[3];
const resp = JSON.parse(fs.readFileSync(respPath, 'utf8'));
const privateKeyPem = fs.readFileSync(privKeyPath, 'utf8');

// Paso 1️⃣ — obtener campos
const xKeyEncB64 = resp.xKey || resp.xkey || resp["x-key"];
const jweCompact = resp.payload || resp.data;

if (!xKeyEncB64 || !jweCompact) {
  console.error('❌ No se encontró xKey o payload en el JSON');
  process.exit(2);
}

// Paso 2️⃣ — descifrar la llave AES256 (RSA → Base64)
let aesKeyBase64;
try {
  const decrypted = crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_PADDING, // igual que en Java (Cipher.getInstance("RSA"))
    },
    Buffer.from(xKeyEncB64, 'base64')
  );
  aesKeyBase64 = decrypted.toString('utf8').trim();
  console.log('🔑 AES key (Base64) recuperada correctamente');
} catch (err) {
  console.error('❌ Error RSA-decrypt:', err.message);
  process.exit(3);
}

// Paso 3️⃣ — decodificar la AES (Base64 → bytes)
const aesKeyBytes = Buffer.from(aesKeyBase64, 'base64');
if (aesKeyBytes.length !== 32) {
  console.warn('⚠️ Longitud AES no esperada:', aesKeyBytes.length);
}

// Paso 4️⃣ — descifrar el JWE
const parts = jweCompact.split('.');
if (parts.length !== 5) {
  console.error('❌ Formato JWE inválido');
  process.exit(4);
}

const [headerB64, , ivB64, cipherB64, tagB64] = parts;
const header = JSON.parse(b64urlToString(headerB64));
console.log('📦 Header JWE:', header);

try {
  const iv = b64urlDecode(ivB64);
  const ciphertext = b64urlDecode(cipherB64);
  const tag = b64urlDecode(tagB64);

  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKeyBytes, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  const plaintext = decrypted.toString('utf8');

  console.log('\n=== ✅ PAYLOAD DESCIFRADO ===\n');
  console.log(plaintext);
  console.log('\n============================\n');
} catch (err) {
  console.error('❌ Error AES-GCM decrypt:', err.message);
  process.exit(5);
}
