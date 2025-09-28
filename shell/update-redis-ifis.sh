#!/bin/bash
# Uso: ./update-redis-user.sh <username> <password> <roles>
# Ejemplo: ./update-redis-user.sh client mypass USER

if [ "$#" -ne 3 ]; then
    echo "Uso: $0 <username> <password> <roles>"
    exit 1
fi

USERNAME="$1"
PASSWORD="$2"
ROLES="$3"

# Ajusta estas rutas según tu entorno Windows
REDIS_CLI="C:/Redis-x64-3.0.504/redis-cli.exe"       # ruta a tu redis-cli en Windows
REDIS_HOST="127.0.0.1"
REDIS_PORT=6379

# Generar hash bcrypt con Java
# Incluye todos los JARs en la misma carpeta
BCRYPT=$(java -cp ".;*" PassGenerator "$PASSWORD")

if [ -z "$BCRYPT" ]; then
    echo "Error: no se pudo generar el hash bcrypt."
    exit 1
fi

# Guardar en Redis en formato JSON
REDIS_VALUE="{\"username\":\"$USERNAME\",\"password\":\"$BCRYPT\",\"roles\":\"$ROLES\"}"

echo "Actualizando Redis: $USERNAME -> $REDIS_VALUE"

# Ejecutar Redis CLI
"$REDIS_CLI" -h $REDIS_HOST -p $REDIS_PORT SET "$USERNAME" "$REDIS_VALUE"
