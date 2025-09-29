#!/bin/bash
set -e

# ==========================
# Configuración inicial
# ==========================
WORKDIR=certs
PASSWORD="clientpass"
DAYS_VALID=365
mkdir -p $WORKDIR
cd $WORKDIR

echo "===> Creando CA raíz"
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1825 -out ca.crt -subj "/C=EC/ST=Pichincha/O=MyCA/CN=RootCA"

# ==========================
# 1. Certificado Cliente válido
# ==========================
echo "===> Cliente certificado válido"
openssl genrsa -out client-valid.key 2048
openssl req -new -key client-valid.key -out client-valid.csr -subj "/C=EC/ST=Pichincha/O=ClienteValido/CN=cliente1"
openssl x509 -req -in client-valid.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client-valid.crt -days $DAYS_VALID -sha256

# ==========================
# 2. Cliente autofirmado (no confiable)
# ==========================
echo "===> Cliente autofirmado (NO confiable)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout client-selfsigned.key -out client-selfsigned.crt -days $DAYS_VALID -subj "/C=EC/ST=Pichincha/O=SelfSigned/CN=cliente-self"

# ==========================
# 3. Cliente expirado
# ==========================
echo "===> Cliente expirado"
openssl genrsa -out client-expired.key 2048
openssl req -new -key client-expired.key -out client-expired.csr -subj "/C=EC/ST=Pichincha/O=ClienteExpirado/CN=cliente-expired"
openssl x509 -req -in client-expired.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client-expired.crt -days 1 -sha256
# Retroceder la fecha del sistema al verificar o usar -days 1 para forzar expiración pronto

# ==========================
# 4. Cliente revocado
# ==========================
echo "===> Cliente revocado"
openssl genrsa -out client-revoked.key 2048
openssl req -new -key client-revoked.key -out client-revoked.csr -subj "/C=EC/ST=Pichincha/O=ClienteRevocado/CN=cliente-revoked"
openssl x509 -req -in client-revoked.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client-revoked.crt -days $DAYS_VALID -sha256

# Generar CRL
echo "===> Generando CRL con certificado revocado"
openssl ca -config <(cat <<EOF
[ ca ]
default_ca = myca
[ myca ]
database = index.txt
new_certs_dir = .
certificate = ca.crt
serial = serial
private_key = ca.key
default_md = sha256
policy = policy_any
[ policy_any ]
countryName = supplied
stateOrProvinceName = supplied
organizationName = supplied
commonName = supplied
EOF
) -gencrl -out ca.crl -keyfile ca.key -cert ca.crt

# ==========================
# 5. Certificado emitido por Gateway
# ==========================
echo "===> Generando CA del Gateway"
openssl genrsa -out gateway-ca.key 4096
openssl req -x509 -new -nodes -key gateway-ca.key -sha256 -days 1825 -out gateway-ca.crt -subj "/C=EC/ST=Pichincha/O=Gateway/CN=GatewayCA"

echo "===> Cliente con certificado emitido por Gateway"
openssl genrsa -out client-gateway.key 2048
openssl req -new -key client-gateway.key -out client-gateway.csr -subj "/C=EC/ST=Pichincha/O=ClienteGateway/CN=cliente-gateway"
openssl x509 -req -in client-gateway.csr -CA gateway-ca.crt -CAkey gateway-ca.key -CAcreateserial -out client-gateway.crt -days $DAYS_VALID -sha256

# ==========================
# Keystores y Truststores
# ==========================
echo "===> Generando Keystore y Truststore"
# Cliente válido
openssl pkcs12 -export -inkey client-valid.key -in client-valid.crt -certfile ca.crt -out client-valid.p12 -password pass:$PASSWORD

# Truststore con CA raíz
keytool -import -trustcacerts -noprompt -alias rootCA -file ca.crt -keystore truststore.jks -storepass $PASSWORD

# Truststore con Gateway CA
keytool -import -trustcacerts -noprompt -alias gatewayCA -file gateway-ca.crt -keystore truststore-gateway.jks -storepass $PASSWORD

echo "===> Script completado. Certificados en carpeta $WORKDIR"
