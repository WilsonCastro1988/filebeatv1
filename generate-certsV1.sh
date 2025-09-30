#!/bin/bash
set -e

BASE_DIR=certs
CA_DIR=$BASE_DIR/ca
FAKE_CA_DIR=$BASE_DIR/fakeca
SERVER_DIR=$BASE_DIR/server
CLIENT_DIR=$BASE_DIR/clients

mkdir -p $CA_DIR $FAKE_CA_DIR $SERVER_DIR $CLIENT_DIR

# ==== 1. Archivos de configuración OpenSSL ====
cat > $BASE_DIR/ca.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn

[ dn ]
C  = EC
O  = MiCA
CN = MiTestCA
EOF

cat > $BASE_DIR/fakeca.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn

[ dn ]
C  = EC
O  = FakeCA
CN = FakeTestCA
EOF

cat > $BASE_DIR/server.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn

[ dn ]
C  = EC
O  = MiOrg
CN = localhost
EOF

cat > $BASE_DIR/client-valid.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn

[ dn ]
C  = EC
O  = Cliente
CN = cliente-valid
EOF

cat > $BASE_DIR/client-expired.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn

[ dn ]
C  = EC
O  = Cliente
CN = cliente-expired
EOF

cat > $BASE_DIR/client-unknown.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn

[ dn ]
C  = EC
O  = Cliente
CN = cliente-desconocido
EOF

cat > $BASE_DIR/client-invalid.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn

[ dn ]
C  = EC
O  = Cliente
CN = cliente-invalid
EOF

# ==== 2. Crear CA raíz ====
echo "=== 1. Crear CA válida ==="
openssl req -x509 -new -nodes -keyout $CA_DIR/ca.key -sha256 -days 3650 \
  -out $CA_DIR/ca.crt -config $BASE_DIR/ca.cnf

echo "=== 2. Crear CA falsa (para certificados inválidos) ==="
openssl req -x509 -new -nodes -keyout $FAKE_CA_DIR/fakeca.key -sha256 -days 3650 \
  -out $FAKE_CA_DIR/fakeca.crt -config $BASE_DIR/fakeca.cnf

# ==== 3. Crear certificado del servidor ====
echo "=== 3. Crear certificado del servidor ==="
openssl req -new -nodes -keyout $SERVER_DIR/server.key -out $SERVER_DIR/server.csr \
  -config $BASE_DIR/server.cnf

openssl x509 -req -in $SERVER_DIR/server.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key \
  -CAcreateserial -out $SERVER_DIR/server.crt -days 365 -sha256

openssl pkcs12 -export -inkey $SERVER_DIR/server.key -in $SERVER_DIR/server.crt \
  -certfile $CA_DIR/ca.crt -out $SERVER_DIR/server-keystore.p12 -password pass:serverpass

keytool -importcert -noprompt -trustcacerts -alias ca \
  -file $CA_DIR/ca.crt -keystore $SERVER_DIR/server-truststore.p12 \
  -storetype PKCS12 -storepass serverpass

# ==== 4. Crear certificados de clientes ====
echo "=== 4. Cliente válido ==="
openssl req -new -nodes -keyout $CLIENT_DIR/client-valid.key -out $CLIENT_DIR/client-valid.csr \
  -config $BASE_DIR/client-valid.cnf

openssl x509 -req -in $CLIENT_DIR/client-valid.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key \
  -CAcreateserial -out $CLIENT_DIR/client-valid.crt -days 365 -sha256

openssl pkcs12 -export -inkey $CLIENT_DIR/client-valid.key -in $CLIENT_DIR/client-valid.crt \
  -certfile $CA_DIR/ca.crt -out $CLIENT_DIR/client-valid-keystore.p12 -password pass:clientpass

keytool -importcert -noprompt -trustcacerts -alias ca \
  -file $CA_DIR/ca.crt -keystore $CLIENT_DIR/client-valid-truststore.p12 \
  -storetype PKCS12 -storepass clientpass

echo "=== 5. Cliente expirado ==="
openssl req -new -nodes -keyout $CLIENT_DIR/client-expired.key -out $CLIENT_DIR/client-expired.csr \
  -config $BASE_DIR/client-expired.cnf

# Usar -days con una validez corta y verificar con la fecha del sistema
# Nota: En Git Bash, las fechas explícitas pueden fallar; usamos -days 1 y ajustamos manualmente si necesario
openssl x509 -req -in $CLIENT_DIR/client-expired.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key \
  -CAcreateserial -out $CLIENT_DIR/client-expired.crt -days 1 -sha256

# Convertir a .p12
openssl pkcs12 -export -inkey $CLIENT_DIR/client-expired.key -in $CLIENT_DIR/client-expired.crt \
  -certfile $CA_DIR/ca.crt -out $CLIENT_DIR/client-expired-keystore.p12 -password pass:clientpass

keytool -importcert -noprompt -trustcacerts -alias ca \
  -file $CA_DIR/ca.crt -keystore $CLIENT_DIR/client-expired-truststore.p12 \
  -storetype PKCS12 -storepass clientpass

echo "=== 6. Cliente con CN desconocido ==="
openssl req -new -nodes -keyout $CLIENT_DIR/client-unknown.key -out $CLIENT_DIR/client-unknown.csr \
  -config $BASE_DIR/client-unknown.cnf

openssl x509 -req -in $CLIENT_DIR/client-unknown.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key \
  -CAcreateserial -out $CLIENT_DIR/client-unknown.crt -days 365 -sha256

openssl pkcs12 -export -inkey $CLIENT_DIR/client-unknown.key -in $CLIENT_DIR/client-unknown.crt \
  -certfile $CA_DIR/ca.crt -out $CLIENT_DIR/client-unknown-keystore.p12 -password pass:clientpass

keytool -importcert -noprompt -trustcacerts -alias ca \
  -file $CA_DIR/ca.crt -keystore $CLIENT_DIR/client-unknown-truststore.p12 \
  -storetype PKCS12 -storepass clientpass

echo "=== 7. Cliente inválido (emitido por FakeCA) ==="
openssl req -new -nodes -keyout $CLIENT_DIR/client-invalid.key -out $CLIENT_DIR/client-invalid.csr \
  -config $BASE_DIR/client-invalid.cnf

openssl x509 -req -in $CLIENT_DIR/client-invalid.csr -CA $FAKE_CA_DIR/fakeca.crt -CAkey $FAKE_CA_DIR/fakeca.key \
  -CAcreateserial -out $CLIENT_DIR/client-invalid.crt -days 365 -sha256

openssl pkcs12 -export -inkey $CLIENT_DIR/client-invalid.key -in $CLIENT_DIR/client-invalid.crt \
  -certfile $FAKE_CA_DIR/fakeca.crt -out $CLIENT_DIR/client-invalid-keystore.p12 -password pass:clientpass

keytool -importcert -noprompt -trustcacerts -alias fakeca \
  -file $FAKE_CA_DIR/fakeca.crt -keystore $CLIENT_DIR/client-invalid-truststore.p12 \
  -storetype PKCS12 -storepass clientpass

echo "✅ Todos los certificados generados en $BASE_DIR/"
