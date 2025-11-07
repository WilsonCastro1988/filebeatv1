#!/bin/bash
set -e

TMP_DIR="./tmp_signcrypt"
mkdir -p "$TMP_DIR"

echo "=== 🚀 EJECUTANDO FLUJO OUT (Firma + Cifrado) ==="
# Aquí asumes que ya tienes tu request y response listos.
# Simulación de response_out.json
RESPONSE_OUT="$TMP_DIR/response_out.json"
REQUEST_IN="$TMP_DIR/request_in.json"
RESPONSE_IN="$TMP_DIR/response_in.json"

# =====================================================
# === FLUJO DE DESCIFRADO LOCAL (DEBUG DE PAYLOAD) ===
# =====================================================
JWE=$(jq -r '.payload' "$RESPONSE_OUT" 2>/dev/null || echo "")
if [[ -z "$JWE" ]]; then
  echo "❌ Error: no se encontró payload JWE en $RESPONSE_OUT"
  exit 1
fi

echo "[INFO] JWE extraído."

# Dividir el JWE
IFS='.' read -r HEADER_B64 ENC_KEY_B64 IV_B64 CIPHERTEXT_B64 TAG_B64 <<< "$JWE"

HEADER_JSON=$(echo "$HEADER_B64" | base64 --decode 2>/dev/null || echo "")
echo "[INFO] Header JSON: $HEADER_JSON"

# Extraer x-key
X_KEY_B64=$(echo "$HEADER_JSON" | jq -r '.["x-key"]' 2>/dev/null || echo "")
if [[ -z "$X_KEY_B64" || "$X_KEY_B64" == "null" ]]; then
  echo "❌ Error: no se encontró x-key en el header protegido."
  exit 1
fi

echo "[INFO] Usando x-key desde header protegido."

# Guardar x-key cifrado
echo "$X_KEY_B64" | base64 --decode > "$TMP_DIR/xkey_encrypted.bin"
echo "[INFO] x-key cifrado guardado en $TMP_DIR/xkey_encrypted.bin ($(stat -c%s "$TMP_DIR/xkey_encrypted.bin") bytes)"

# === RSA Decrypt ===
RSA_PRIVKEY="C:/etc/tls/rsa-keys/PRIVATEIN0002.pem"

AES_KEY_RAW="$TMP_DIR/aes_key_after_rsa_pkcs1.bin"
openssl pkeyutl -decrypt -inkey "$RSA_PRIVKEY" -in "$TMP_DIR/xkey_encrypted.bin" -out "$AES_KEY_RAW" || true

if [[ ! -s "$AES_KEY_RAW" ]]; then
  echo "❌ Error: RSA decrypt falló, no se obtuvo clave AES."
  exit 1
fi

# Filtrar solo bytes imprimibles si no hay strings
if command -v strings >/dev/null; then
  AES_KEY=$(strings "$AES_KEY_RAW" | tr -d '\n')
else
  AES_KEY=$(xxd -p "$AES_KEY_RAW" | tr -d '\n' | head -c 64)
fi

if [[ -z "$AES_KEY" ]]; then
  echo "❌ No se pudo extraer la clave AES."
  exit 1
fi

echo "[INFO] Clave AES (hex): ${AES_KEY:0:16}... (ocultando resto)"
echo "$AES_KEY" > "$TMP_DIR/aes_key_hex.txt"

# === Convertir todos los elementos del JWE ===
IV_HEX=$(echo "$IV_B64" | base64 --decode | xxd -p | tr -d '\n')
CIPHER_BIN="$TMP_DIR/cipher.bin"
TAG_HEX=$(echo "$TAG_B64" | base64 --decode | xxd -p | tr -d '\n')
echo "$CIPHERTEXT_B64" | base64 --decode > "$CIPHER_BIN"

echo "[INFO] AES raw key size: $(wc -c <"$AES_KEY_RAW") bytes"
echo "[INFO] IV bytes: $(echo -n "$IV_HEX" | wc -c) hexchars"
echo "[INFO] TAG bytes: $(echo -n "$TAG_HEX" | wc -c) hexchars"
echo "[INFO] CIPHER bytes: $(stat -c%s "$CIPHER_BIN")"
echo "[INFO] AAD (protected header base64url) length=${#HEADER_B64}"

# === Intentar descifrar con openssl (modo GCM) ===
DECRYPTED_PAYLOAD="$TMP_DIR/payload_decrypted.json"

echo "[INFO] Intentando descifrar con openssl (AES-256-GCM)..."
openssl aes-256-gcm -d \
  -K "$AES_KEY" \
  -iv "$IV_HEX" \
  -in "$CIPHER_BIN" \
  -out "$DECRYPTED_PAYLOAD" \
  -aad "$(echo -n "$HEADER_B64" | base64 --decode 2>/dev/null)" \
  -tag "$TAG_HEX" 2>/dev/null || true

if [[ ! -s "$DECRYPTED_PAYLOAD" ]]; then
  echo "[WARN] openssl no logró descifrar el payload."
  if command -v python3 >/dev/null; then
    echo "[INFO] Intentando fallback con Python (cryptography)..."
    python3 - <<'PYCODE'
import base64, binascii, json, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path

tmp = Path("./tmp_signcrypt")
key = binascii.unhexlify(Path(tmp/"aes_key_hex.txt").read_text().strip())
iv = binascii.unhexlify(sys.argv[1])
tag = binascii.unhexlify(sys.argv[2])
ct = open(tmp/"cipher.bin","rb").read()
aad = base64.urlsafe_b64decode(sys.argv[3] + "==")

aesgcm = AESGCM(key)
try:
    plaintext = aesgcm.decrypt(iv, ct+tag, aad)
    (tmp/"payload_decrypted.json").write_bytes(plaintext)
    print("[✅] Descifrado con Python OK")
except Exception as e:
    print("[❌] Error al descifrar con Python:", e)
PYCODE "$IV_HEX" "$TAG_HEX" "$HEADER_B64"
  else
    echo "⚠️ Python no disponible; no se pudo usar fallback."
  fi
fi

if [[ -s "$DECRYPTED_PAYLOAD" ]]; then
  echo "✅ Payload descifrado correctamente en $DECRYPTED_PAYLOAD"
else
  echo "❌ Error: no se pudo descifrar el payload con AES."
fi
