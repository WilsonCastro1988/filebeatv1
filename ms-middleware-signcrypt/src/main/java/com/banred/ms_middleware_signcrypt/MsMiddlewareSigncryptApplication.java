package com.banred.ms_middleware_signcrypt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class MsMiddlewareSigncryptApplication {

    public static void main(String[] args) {
        SpringApplication.run(MsMiddlewareSigncryptApplication.class, args);
    }
}
