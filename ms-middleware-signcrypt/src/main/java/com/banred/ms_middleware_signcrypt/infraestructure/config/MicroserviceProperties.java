package com.banred.ms_middleware_signcrypt.infraestructure.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "microservice.parameters")
public class MicroserviceProperties {

    private int redisPort;
    private String redisUsername;
    private String redisPassword;
    private String redisHostname;
    private String rutaConfigXml;
    private String rutaCrl;
    private String rutaRsa;
    private long expirySeconds;


}
