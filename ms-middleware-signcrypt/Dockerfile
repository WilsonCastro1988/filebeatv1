# Usar una imagen base JRE ligera para producción
FROM amazoncorretto:17.0.16-alpine3.21
LABEL maintener="wcastro@banred.fin.ec"
LABEL Description="Microservicio GatewaySeguridad Pago Directo"

# Actualiza el índice de paquetes e instala dependencias necesarias
RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache openssl

ENV TZ=America/Guayaquil

ARG SERVER_PORT=8443
ARG user=devopsa
ARG group=devopsa
ARG home=/home/$user
ARG keyalias=ws-security-spring-boot
ARG domain=banred.fin.ec
ARG organization=BANRED
ARG JAR_FILE=target/*.jar

# RUN groupadd -g 1337 $user && useradd -d $home -u 1337 -s /bin/bash -g $group $user
RUN addgroup -g 1337 $group && adduser -D -h $home -u 1337 -G $group $user

RUN mkdir -p $home/app/logs/ && chown -R $user:$group $home/app/

RUN mkdir -p /etc/ssl/certs/

RUN keytool -genkey -alias $keyalias -keyalg RSA -keysize 4096 -sigalg SHA256withRSA -storetype PKCS12 -keystore /etc/ssl/certs/localhost.p12 -dname CN=$domain,OU=$organization,O=$organization,L=$city,C=CN -validity 3650 -storepass $SSL_TRUSTSTORE_PASSWORD -keypass $SSL_KEYSTORE_PASSWORD -ext san=dns:$domain

RUN chown -R $user:$group /etc/ssl/certs/ && chmod -R 700 /etc/ssl/certs/

RUN mkdir -p $home/app/certs/ && chown -R $user:$group $home/app/certs/ && chmod -R 700 $home/app/certs/

USER $user

# Establecer el directorio de trabajo
WORKDIR $home/app/

# Copiar el JAR ejecutable de la aplicación
COPY ${JAR_FILE} app.jar

# Exponer el puerto 8443 (HTTPS para mTLS)
EXPOSE ${SERVER_PORT}

# Comando para ejecutar la aplicación
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
