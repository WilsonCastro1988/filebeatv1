# 🛡️ ms-middleware-signcrypt

Microservicio de **firma y cifrado (Sign & Crypt)** desarrollado en **Spring Boot 3 + Java 17**, con integración a **Redis**, **Elasticsearch**, y soporte para **TLS, JWE y JWS**.

Autor: **Wilson Castro**  
Email: **wcastro@banred.fin.ec**

---

## 📋 Índice

1. [📦 Requisitos previos](#-requisitos-previos)
2. [⚙️ Estructura del proyecto](#️-estructura-del-proyecto)
3. [🚀 Despliegue en entorno de desarrollo (DEV)](#-despliegue-en-entorno-de-desarrollo-dev)
4. [🏭 Despliegue en entorno de producción (PROD)](#-despliegue-en-entorno-de-producción-prod)
5. [🔎 Verificación y pruebas](#-verificación-y-pruebas)
6. [🧰 Comandos útiles](#-comandos-útiles)
7. [🧾 Notas adicionales](#-notas-adicionales)

---

## 📦 Requisitos previos

Antes de ejecutar los despliegues asegúrate de tener instalado:

| Componente | Versión mínima | Propósito |
|-------------|----------------|------------|
| 🐳 Docker | 24.x | Motor de contenedores |
| 🐙 Docker Compose | 2.20+ | Orquestación local |
| ☕ Java | 17+ | Entorno de ejecución de la app |
| 🧱 Maven | 3.9+ | Construcción del proyecto |
| 🧰 Git | opcional | Control de versiones |

> 💡 *Si usas Windows, ejecuta todos los comandos en PowerShell o WSL2 con permisos administrativos.*

---

## ⚙️ Estructura del proyecto

```
📦 ms-middleware-signcrypt/
 ├── src/                              # Código fuente (Spring Boot)
 ├── pom.xml                           # Configuración Maven
 ├── Dockerfile                        # Imagen base del microservicio
 ├── docker-compose.yml                 # Despliegue para desarrollo
 ├── docker-compose.prod.yml            # Despliegue para producción
 ├── .env                               # Variables de entorno sensibles
 ├── logs/                              # Carpeta persistente de logs
 └── tls/                               # Archivos de certificados
      ├── config-service.xml
      ├── crl/crl.der
      ├── rsa-keys/{private.pem, public.pem}
      └── keystore/keystore.jks
```

---

## 🚀 Despliegue en entorno de desarrollo (DEV)

Este entorno está pensado para **pruebas locales** con acceso directo desde `http://localhost:8442`.

### 🔹 1. Construir la imagen
```bash
docker compose build
```

### 🔹 2. Levantar el entorno
```bash
docker compose up -d
```

### 🔹 3. Verificar contenedores
```bash
docker ps
```

Deberías ver algo como:
```
CONTAINER ID   NAME                      STATUS          PORTS
f0a1234abcde   ms-middleware-signcrypt   Up 1 min        0.0.0.0:8442->8442/tcp
b2b4321cdef12  redis                     Up 1 min        6379/tcp
a4c98dd4ee43   elasticsearch             Up 1 min        9200/tcp
```

### 🔹 4. Acceso a la aplicación
- URL base: [http://localhost:8442/api](http://localhost:8442/api)
- Logs locales: carpeta `./logs/`

### 🔹 5. Detener el entorno
```bash
docker compose down
```

---

## 🏭 Despliegue en entorno de producción (PROD)

Este entorno usa configuración segura: **TLS**, **Redis protegido**, **volúmenes persistentes**, y variables externas.

### 🔹 1. Configurar variables de entorno

Crea o edita el archivo `.env`:

```env
REDIS_PASSWORD=R3d1s@SecurePwd
TLS_KEYSTORE_PASSWORD=MyKeystorePass123
SPRING_PROFILES_ACTIVE=prod
```

### 🔹 2. Construir imagen de producción
```bash
docker compose -f docker-compose.prod.yml build
```

### 🔹 3. Levantar entorno seguro
```bash
docker compose -f docker-compose.prod.yml up -d
```

### 🔹 4. Verificar servicios
```bash
docker compose -f docker-compose.prod.yml ps
```

### 🔹 5. Validar acceso
Accede a la aplicación (puerto expuesto):
```
https://<host-servidor>:8442/api
```

> ⚠️ Si usas certificados autofirmados, agrega una excepción en el navegador o usa `curl -k`.

---

## 🔎 Verificación y pruebas

### ✅ Verificar logs
```bash
docker logs -f ms-middleware-signcrypt
```

### ✅ Probar endpoints
```bash
curl http://localhost:8442/api/actuator/health
```

### ✅ Revisar Redis
```bash
docker exec -it redis redis-cli -a R3d1s@SecurePwd ping
```

### ✅ Revisar Elasticsearch
```bash
curl http://localhost:9200/_cluster/health?pretty
```

---

## 🧰 Comandos útiles

| Acción | Comando |
|--------|----------|
| Ver imágenes locales | `docker images` |
| Ver contenedores activos | `docker ps` |
| Detener entorno dev | `docker compose down` |
| Detener entorno prod | `docker compose -f docker-compose.prod.yml down` |
| Limpiar caché de imágenes | `docker system prune -f` |
| Reconstruir desde cero | `docker compose build --no-cache` |

---

## 🧾 Notas adicionales

- 🧩 **Kubernetes:** Este microservicio puede desplegarse fácilmente en K8s usando el manifiesto `ms-middleware-signcrypt.yaml` (ver carpeta `/k8s` si existe).
- 🔐 **TLS:** Los certificados se deben montar en `/etc/tls/keystore/keystore.jks` y configurarse con `TLS_KEYSTORE_PASSWORD`.
- 📊 **Logs:** Se guardan en `./logs/` fuera del contenedor, rotando automáticamente según `logback` (`7 días`, `1GB`).
- 🧠 **Configuraciones dinámicas:** Las variables `SERVER_PORT`, `REDIS_HOSTNAME`, y `EXPIRY_SECONDS` pueden ajustarse desde el entorno sin recompilar.
- 🧰 **Debug:** Si necesitas depurar TLS, añade a `JAVA_OPTS`:
  ```bash
  -Djavax.net.debug=ssl:handshake:verbose
  ```

---

## 🏁 Conclusión

Este entorno proporciona una **arquitectura lista para desarrollo y producción**, con:
- Microservicio independiente y portable.
- Seguridad mediante TLS y Redis protegido.
- Persistencia de logs y datos.
- Orquestación con Docker Compose.
- Compatibilidad total con Kubernetes.

---

> **© 2025 - Banred / Wilson Castro**  
> Uso interno y pruebas del microservicio `ms-middleware-signcrypt`.
