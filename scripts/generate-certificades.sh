#!/bin/bash
# ============================================================
# Script para generar certificados para escenarios mTLS
# Escenario 1: Cliente usa certificado emitido por CA propia
# Escenario 2: Cliente usa certificado emitido por Gateway
# Escenario 3: Validación mutua (ambos confían uno en otro)
# ============================================================

set -e

OUTPUT_DIR=certs-mtls
mkdir -p $OUTPUT_DIR
cd $OUTPUT_DIR

# =======================
# 1. Crear CA del Cliente
# =======================
echo ">> Generando CA del Cliente..."
openssl genrsa -out ca-cliente.key 4096
openssl req -x509 -new -nodes -key ca-cliente.key -sha256 -days 3650 \
  -subj "/C=EC/ST=Pichincha/L=Quito/O=ClienteOrg/CN=CACliente" \
  -out ca-cliente.crt

# =======================
# 2. Crear CA del Gateway
# =======================
echo ">> Generando CA del Gateway..."
openssl genrsa -out ca-gateway.key 4096
openssl req -x509 -new -nodes -key ca-gateway.key -sha256 -days 3650 \
  -subj "/C=EC/ST=Pichincha/L=Quito/O=GatewayOrg/CN=CAGateway" \
  -out ca-gateway.crt

# =======================
# Escenario 1: Cliente certificado por su CA
# =======================
echo ">> Generando certificado Cliente con su propia CA..."
openssl genrsa -out client1.key 2048
openssl req -new -key client1.key \
  -subj "/C=EC/ST=Pichincha/L=Quito/O=ClienteOrg/CN=cliente1" \
  -out client1.csr
openssl x509 -req -in client1.csr -CA ca-cliente.crt -CAkey ca-cliente.key \
  -CAcreateserial -out client1.crt -days 365 -sha256

# =======================
# Escenario 2: Cliente certificado por el Gateway
# =======================
echo ">> Generando certificado Cliente emitido por Gateway..."
openssl genrsa -out client2.key 2048
openssl req -new -key client2.key \
  -subj "/C=EC/ST=Pichincha/L=Quito/O=ClienteOrg/CN=cliente2" \
  -out client2.csr
openssl x509 -req -in client2.csr -CA ca-gateway.crt -CAkey ca-gateway.key \
  -CAcreateserial -out client2.crt -days 365 -sha256

# =======================
# Certificado del Gateway (firmado por su propia CA)
# =======================
echo ">> Generando certificado del Gateway..."
openssl genrsa -out gateway.key 2048
openssl req -new -key gateway.key \
  -subj "/C=EC/ST=Pichincha/L=Quito/O=GatewayOrg/CN=gateway" \
  -out gateway.csr
openssl x509 -req -in gateway.csr -CA ca-gateway.crt -CAkey ca-gateway.key \
  -CAcreateserial -out gateway.crt -days 365 -sha256

# =======================
# Exportar a Keystore y Truststore (para Java / APIM)
# =======================
PASSWORD=changeit

echo ">> Creando keystores y truststores..."

# Cliente 1 (escenario 1)
openssl pkcs12 -export -in client1.crt -inkey client1.key \
  -certfile ca-cliente.crt -out client1-keystore.p12 -password pass:$PASSWORD
keytool -import -trustcacerts -alias ca-cliente -file ca-cliente.crt \
  -keystore client1-truststore.jks -storepass $PASSWORD -noprompt

# Cliente 2 (escenario 2)
openssl pkcs12 -export -in client2.crt -inkey client2.key \
  -certfile ca-gateway.crt -out client2-keystore.p12 -password pass:$PASSWORD
keytool -import -trustcacerts -alias ca-gateway -file ca-gateway.crt \
  -keystore client2-truststore.jks -storepass $PASSWORD -noprompt

# Gateway (escenario 3 mutua validación)
openssl pkcs12 -export -in gateway.crt -inkey gateway.key \
  -certfile ca-gateway.crt -out gateway-keystore.p12 -password pass:$PASSWORD
keytool -import -trustcacerts -alias ca-cliente -file ca-cliente.crt \
  -keystore gateway-truststore.jks -storepass $PASSWORD -noprompt

echo "===================================================="
echo "✅ Certificados generados en la carpeta $OUTPUT_DIR"
echo "Escenario 1: client1.crt/.key + client1-keystore.p12 + client1-truststore.jks"
echo "Escenario 2: client2.crt/.key + client2-keystore.p12 + client2-truststore.jks"
echo "Escenario 3: gateway.crt/.key + gateway-keystore.p12 + gateway-truststore.jks"
echo "===================================================="
