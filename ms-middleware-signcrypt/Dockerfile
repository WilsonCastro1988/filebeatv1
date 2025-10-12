# Usar una imagen base de OpenJDK 17 (compatible con Spring Boot)
FROM openjdk:17-jdk-slim

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar el JAR de la aplicación (asumiendo que está en el directorio target)
COPY target/ms-middleware-signcrypt-1.0.0.jar app.jar

# Exponer el puerto 8442 (HTTPS para mTLS)
EXPOSE 8442

# Configurar variables de entorno desde properties.yaml
ENV SERVER_PORT=8442
ENV REDIS_PORT=6379
ENV REDIS_HOSTNAME=redis
ENV RUTA_CONFIG_XML=/etc/tls/config-service.xml
ENV RUTA_CRL=/etc/tls/certs/ca/crl/crl.der
ENV RUTA_RSA=/etc/tls/rsa-keys
ENV EXPIRY_SECONDS=300
ENV SPRING_JACKSON_DEFAULT_PROPERTY_INCLUSION=non-null
ENV SPRING_JACKSON_TIME_ZONE=GMT-5
ENV LOGGING_FILE_NAME=/logs/app.log
ENV LOGGING_LOGBACK_ROLLINGPOLICY_FILE_NAME_PATTERN=/logs/app.%d{yyyy-MM-dd}.log
ENV LOGGING_LOGBACK_ROLLINGPOLICY_MAX_HISTORY=7
ENV LOGGING_LOGBACK_ROLLINGPOLICY_TOTAL_SIZE_CAP=1GB

# Comando para ejecutar la aplicación
ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar"]
