FROM eclipse-temurin:17-jdk-jammy
VOLUME /tmp
COPY target/mtls-mock-server-1.0.0.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
