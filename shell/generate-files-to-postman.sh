#!/bin/bash

# Configuración
KEYSTORE="C:/etc/tls/crt-casos/caso1/client_valid-keystore.p12"
PASSWORD="clientpass"
CRT_OUT="C:/etc/tls/crt-casos/caso1/client.crt"
KEY_OUT="C:/etc/tls/crt-casos/caso1/client.key"
PFX_OUT="C:/etc/tls/crt-casos/caso1/client.pfx"

echo "🔓 Extrayendo certificado (.crt)..."
openssl pkcs12 -in $KEYSTORE -clcerts -nokeys -out $CRT_OUT -passin pass:$PASSWORD

echo "🔐 Extrayendo clave privada (.key)..."
openssl pkcs12 -in $KEYSTORE -nocerts -out client-encrypted.key -passin pass:$PASSWORD -passout pass:$PASSWORD

echo "🔓 Desencriptando clave privada..."
openssl rsa -in client-encrypted.key -out $KEY_OUT -passin pass:$PASSWORD
rm client-encrypted.key

echo "📦 Generando archivo .pfx para Postman..."
openssl pkcs12 -export -out $PFX_OUT -inkey $KEY_OUT -in $CRT_OUT -passout pass:$PASSWORD

echo "✅ Archivos generados:"
echo " - Certificado: $CRT_OUT"
echo " - Clave privada: $KEY_OUT"
echo " - Archivo PFX: $PFX_OUT"