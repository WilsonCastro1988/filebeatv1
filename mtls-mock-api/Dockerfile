# Usar una imagen base JRE ligera para producción
FROM eclipse-temurin:17-jre

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar el JAR ejecutable de la aplicación
COPY target/mtls-mock-api-1.0.0.jar app.jar

# Copiar certificados SSL al contenedor
COPY src/main/resources/tls/certs/server/server-keystore.p12 /etc/tls/certs/server/server-keystore.p12
COPY src/main/resources/tls/certs/server/server-truststore.p12 /etc/tls/certs/server/server-truststore.p12

# Exponer el puerto 8443 (HTTPS para mTLS)
EXPOSE 8443

# Configurar variables de entorno para producción
ENV SERVER_PORT=8443
ENV SERVER_ADDRESS=0.0.0.0
ENV LOGGING_LEVEL_ROOT=INFO
ENV LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_SECURITY=INFO
ENV SERVER_SSL_KEY_STORE=/etc/tls/certs/server/server-keystore.p12
ENV SERVER_SSL_KEY_STORE_PASSWORD=serverpass
ENV SERVER_SSL_KEY_STORE_TYPE=PKCS12
ENV SERVER_SSL_KEY_ALIAS=server
ENV SERVER_SSL_TRUST_STORE=/etc/tls/certs/server/server-truststore.p12
ENV SERVER_SSL_TRUST_STORE_PASSWORD=serverpass
ENV SERVER_SSL_TRUST_STORE_TYPE=PKCS12
ENV SERVER_SSL_CLIENT_AUTH=need
ENV SPRING_DATA_REDIS_HOST=redis
ENV SPRING_DATA_REDIS_PORT=6379
ENV SPRING_DATA_REDIS_PASSWORD=Passw0rd
ENV SPRING_DATA_REDIS_TIMEOUT=60000
ENV LOGGING_FILE_NAME=/logs/mockserver.log
ENV LOGGING_LOGBACK_ROLLINGPOLICY_FILE_NAME_PATTERN=/logs/mockserver.%d{yyyy-MM-dd}.log
ENV LOGGING_LOGBACK_ROLLINGPOLICY_MAX_HISTORY=7
ENV LOGGING_LOGBACK_ROLLINGPOLICY_TOTAL_SIZE_CAP=1GB
ENV JAVA_OPTS="-Xms256m -Xmx512m -Djava.security.egd=file:/dev/./urandom"

# Comando para ejecutar la aplicación
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
