package com.banred.ms_middleware_signcrypt.infraestructure.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "microservice.parameters")
public class MicroserviceProperties {

    private int REDIS_PORT;
    private String REDIS_USERNAME;
    private String REDIS_PASSWORD;
    private String REDIS_HOSTNAME;
    private String RUTA_CONFIG_XML;
    private String RUTA_CRL;
    private String RUTA_RSA;


}