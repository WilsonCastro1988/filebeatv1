#!/bin/bash
set -e

BASE_DIR=certs
CA_DIR=$BASE_DIR/ca
CRL_DIR=$CA_DIR/crl
FAKE_CA_DIR=$BASE_DIR/fakeca
SERVER_DIR=$BASE_DIR/server
CLIENT_DIR=$BASE_DIR/clients
CA_INDEX="$CA_DIR/index.txt"


mkdir -p $CA_DIR $FAKE_CA_DIR $SERVER_DIR $CLIENT_DIR "$CA_DIR"/{certs,crl,newcerts,private}
touch "$CA_INDEX"

# ==== 1. Archivos de configuración OpenSSL ====
cat > $BASE_DIR/ca.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_ca

[ dn ]
C  = EC
O  = MiCA
CN = MiTestCA

[ v3_ca ]
basicConstraints = CA:true
keyUsage = keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ./certs/ca
certs             = $CA_DIR/certs
crl_dir           = $CA_DIR/crl
new_certs_dir     = $CA_DIR/newcerts
database          = $CA_DIR/index.txt
serial            = $CA_DIR/serial
#crlnumber         = $CA_DIR/crlnumber
crl               = $CA_DIR/crl.pem
private_key       = $CA_DIR/ca.key
certificate       = $CA_DIR/ca.crt
default_days      = 365
default_md        = sha256
policy            = policy_match
x509_extensions   = v3_ca
crl_extensions    = crl_ext
default_crl_days  = 30  # Número de días hasta la próxima CRL

[ policy_match ]
countryName             = match
organizationName        = match
commonName              = supplied

[ crl_ext ]
authorityKeyIdentifier = keyid:always
issuerAltName          = issuer:copy
EOF

cat > $BASE_DIR/fakeca.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_ca

[ dn ]
C  = EC
O  = FakeCA
CN = FakeTestCA

[ v3_ca ]
basicConstraints = CA:true
keyUsage = keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

cat > $BASE_DIR/server.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req

[ dn ]
C  = EC
O  = MiOrg
CN = localhost

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
crlDistributionPoints = URI:file:///C:/etc/tls/certs/ca/crl/crl.pem
EOF

cat > $BASE_DIR/client-valid.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req


[ dn ]
C  = EC
O  = Cliente
CN = cliente-valid

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
crlDistributionPoints = URI:file:///C:/etc/tls/certs/ca/crl/crl.pem
EOF

cat > $BASE_DIR/client-expired.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req


[ dn ]
C  = EC
O  = Cliente
CN = cliente-expired

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
EOF

cat > $BASE_DIR/client-unknown.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req


[ dn ]
C  = EC
O  = Cliente
CN = cliente-desconocido
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
EOF

cat > $BASE_DIR/client-invalid.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req


[ dn ]
C  = EC
O  = Cliente
CN = cliente-invalid

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
EOF

# ==== 2. Crear CA raíz ====
echo "=== 1. Crear CA válida ==="
openssl req -x509 -new -nodes -keyout $CA_DIR/ca.key -sha256 -days 3650 \
  -out $CA_DIR/ca.crt -config $BASE_DIR/ca.cnf -extensions v3_ca

echo "=== 2. Crear CA falsa (para certificados inválidos) ==="
openssl req -x509 -new -nodes -keyout $FAKE_CA_DIR/fakeca.key -sha256 -days 3650 \
  -out $FAKE_CA_DIR/fakeca.crt -config $BASE_DIR/fakeca.cnf -extensions v3_ca

# ==== 3. Crear certificado del servidor ====
echo "=== 3. Crear certificado del servidor ==="
openssl req -new -nodes -keyout $SERVER_DIR/server.key -out $SERVER_DIR/server.csr \
  -config $BASE_DIR/server.cnf

openssl x509 -req -in $SERVER_DIR/server.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key \
  -CAcreateserial -out $SERVER_DIR/server.crt -days 365 -sha256

# Exportar a PKCS12 con un alias explícito 'server' para el keystore
openssl pkcs12 -export -inkey $SERVER_DIR/server.key -in $SERVER_DIR/server.crt \
  -certfile $CA_DIR/ca.crt -out $SERVER_DIR/server-keystore.p12 -name server -password pass:serverpass

# Crear truststore con la CA (alias 'ca' para la CA)
keytool -importcert -noprompt -trustcacerts -alias ca \
  -file $CA_DIR/ca.crt -keystore $SERVER_DIR/server-truststore.p12 \
  -storetype PKCS12 -storepass serverpass

# ==== 4. Crear certificados de clientes ====
echo "=== 4. Cliente válido ==="
openssl req -new -nodes -keyout $CLIENT_DIR/client-valid.key -out $CLIENT_DIR/client-valid.csr \
  -config $BASE_DIR/client-valid.cnf

openssl x509 -req -in $CLIENT_DIR/client-valid.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key \
  -CAcreateserial -out $CLIENT_DIR/client-valid.crt -days 365 -sha256 -extfile $BASE_DIR/client-valid.cnf \
  -extensions v3_req

openssl pkcs12 -export -inkey $CLIENT_DIR/client-valid.key -in $CLIENT_DIR/client-valid.crt \
  -certfile $CA_DIR/ca.crt -out $CLIENT_DIR/client-valid-keystore.p12 -name client-valid -password pass:clientpass

keytool -importcert -noprompt -trustcacerts -alias ca \
  -file $CA_DIR/ca.crt -keystore $CLIENT_DIR/client-valid-truststore.p12 \
  -storetype PKCS12 -storepass clientpass

echo "=== 5. Cliente expirado ==="
openssl req -new -nodes -keyout $CLIENT_DIR/client-expired.key -out $CLIENT_DIR/client-expired.csr \
  -config $BASE_DIR/client-expired.cnf

# Usar -days 1 con un enfoque simplificado (expirará 1 día después de la generación)
# Nota: Dado que las fechas explícitas fallan, usa un día pasado manualmente si necesario
openssl x509 -req -in $CLIENT_DIR/client-expired.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key \
  -CAcreateserial -out $CLIENT_DIR/client-expired.crt -days 1 -sha256 -extfile $BASE_DIR/client-valid.cnf \
  -extensions v3_req

# Verificar fechas generadas
echo "Verificando fechas del certificado expirado..."
openssl x509 -in $CLIENT_DIR/client-expired.crt -noout -dates

# Advertencia: Si la fecha es 30/09/2025, el certificado no está expirado aún. Ajusta manualmente:
echo "ADVERTENCIA: Si la fecha 'notAfter' es 30/09/2025, el certificado no está expirado. Usa el siguiente comando manual para ajustarlo:"
echo "openssl x509 -in $CLIENT_DIR/client-expired.crt -out $CLIENT_DIR/client-expired-adjusted.crt -startdate 20240101000000Z -enddate 20240102000000Z"
echo "Luego, actualiza el .p12 con: openssl pkcs12 -export -inkey $CLIENT_DIR/client-expired.key -in $CLIENT_DIR/client-expired-adjusted.crt -certfile $CA_DIR/ca.crt -out $CLIENT_DIR/client-expired-keystore.p12 -name client-expired -password pass:clientpass"

openssl pkcs12 -export -inkey $CLIENT_DIR/client-expired.key -in $CLIENT_DIR/client-expired.crt \
  -certfile $CA_DIR/ca.crt -out $CLIENT_DIR/client-expired-keystore.p12 -name client-expired -password pass:clientpass

keytool -importcert -noprompt -trustcacerts -alias ca \
  -file $CA_DIR/ca.crt -keystore $CLIENT_DIR/client-expired-truststore.p12 \
  -storetype PKCS12 -storepass clientpass

echo "=== 6. Cliente con CN desconocido ==="
openssl req -new -nodes -keyout $CLIENT_DIR/client-unknown.key -out $CLIENT_DIR/client-unknown.csr \
  -config $BASE_DIR/client-unknown.cnf

openssl x509 -req -in $CLIENT_DIR/client-unknown.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key \
  -CAcreateserial -out $CLIENT_DIR/client-unknown.crt -days 365 -sha256 -extfile $BASE_DIR/client-valid.cnf \
  -extensions v3_req

openssl pkcs12 -export -inkey $CLIENT_DIR/client-unknown.key -in $CLIENT_DIR/client-unknown.crt \
  -certfile $CA_DIR/ca.crt -out $CLIENT_DIR/client-unknown-keystore.p12 -name client-unknown -password pass:clientpass

keytool -importcert -noprompt -trustcacerts -alias ca \
  -file $CA_DIR/ca.crt -keystore $CLIENT_DIR/client-unknown-truststore.p12 \
  -storetype PKCS12 -storepass clientpass

echo "=== 7. Cliente inválido (emitido por FakeCA) ==="
openssl req -new -nodes -keyout $CLIENT_DIR/client-invalid.key -out $CLIENT_DIR/client-invalid.csr \
  -config $BASE_DIR/client-invalid.cnf

openssl x509 -req -in $CLIENT_DIR/client-invalid.csr -CA $FAKE_CA_DIR/fakeca.crt -CAkey $FAKE_CA_DIR/fakeca.key \
  -CAcreateserial -out $CLIENT_DIR/client-invalid.crt -days 365 -sha256 -extfile $BASE_DIR/client-valid.cnf \
  -extensions v3_req

openssl pkcs12 -export -inkey $CLIENT_DIR/client-invalid.key -in $CLIENT_DIR/client-invalid.crt \
  -certfile $FAKE_CA_DIR/fakeca.crt -out $CLIENT_DIR/client-invalid-keystore.p12 -name client-invalid -password pass:clientpass

keytool -importcert -noprompt -trustcacerts -alias fakeca \
  -file $FAKE_CA_DIR/fakeca.crt -keystore $CLIENT_DIR/client-invalid-truststore.p12 \
  -storetype PKCS12 -storepass clientpass

# ==== 8. Inicialización opcional de Redis (si Redis está corriendo localmente) ====
echo "=== 8. Inicialización opcional de Redis ==="
if command -v redis-cli &> /dev/null; then
    echo "Inicializando usuarios en Redis..."
    redis-cli -h localhost -p 6379 SET "client1" "{\"username\":\"client1\",\"password\":null,\"roles\":[\"USER\"]}"
    redis-cli -h localhost -p 6379 SET "cliente-valid" "{\"username\":\"cliente-valid\",\"password\":null,\"roles\":[\"USER\"]}"
    redis-cli -h localhost -p 6379 SET "cliente-expired" "{\"username\":\"cliente-expired\",\"password\":null,\"roles\":[\"USER\"]}"
    redis-cli -h localhost -p 6379 SET "cliente-desconocido" "{\"username\":\"cliente-desconocido\",\"password\":null,\"roles\":[\"USER\"]}"
    redis-cli -h localhost -p 6379 SET "cliente-invalid" "{\"username\":\"cliente-invalid\",\"password\":null,\"roles\":[\"USER\"]}"
else
    echo "redis-cli no encontrado. Omite la inicialización de Redis. Asegúrate de configurarlo manualmente o en la aplicación."
fi

echo "✅ Todos los certificados generados en $BASE_DIR/ $CA_DIR/"
echo "<=============================================================>"
echo "✅ Revocanbdo certificados en  $BASE_DIR/ "

# ==== 4. Revocar certificados ====
#openssl ca -config $BASE_DIR/ca.cnf -revoke $CLIENT_DIR/client-valid.crt
#openssl ca -config $BASE_DIR/ca.cnf -revoke $CLIENT_DIR/client-expired.crt
#openssl ca -config $BASE_DIR/ca.cnf -revoke $CLIENT_DIR/client-invalid.crt

# ==== 5. Generar CRL ====
openssl ca -config $BASE_DIR/ca.cnf -gencrl -out $CRL_DIR/crl.pem

# ==== 6. Verificar CRL ====
openssl crl -in $CRL_DIR/crl.pem -text -noout
openssl crl -in $CRL_DIR/crl.pem -out $CRL_DIR/crl.der -outform DER
openssl crl -in $CRL_DIR/crl.der -inform DER -text -noout
