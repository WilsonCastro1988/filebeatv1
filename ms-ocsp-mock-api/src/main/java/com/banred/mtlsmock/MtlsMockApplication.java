package com.banred.mtlsmock;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class MtlsMockApplication {
    public static void main(String[] args) {
        SpringApplication.run(MtlsMockApplication.class, args);
        buildEncryptor();

    }

    /**
     * 🔐 Bean de Jasypt para desencriptar automáticamente propiedades ENC(...)
     */
    @Bean(name = "jasyptStringEncryptor")
    public StringEncryptor stringEncryptor() {
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();

        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        // 🔹 Clave secreta, debe estar en variable de entorno SECRET_KEY
        config.setPassword(System.getenv("SECRET_KEY"));

        // 🔹 Configuración segura (igual que tu YML)
        config.setAlgorithm("PBEWITHHMACSHA512ANDAES_256");
        config.setKeyObtentionIterations("100000");
        config.setPoolSize("1");
        config.setProviderName("SunJCE");
        config.setSaltGeneratorClassName("org.jasypt.salt.RandomSaltGenerator");
        config.setIvGeneratorClassName("org.jasypt.iv.RandomIvGenerator");
        config.setStringOutputType("base64");

        encryptor.setConfig(config);
        return encryptor;
    }


    private static void buildEncryptor() {
        // 🔐 Tu clave secreta (debe coincidir con SECRET_KEY del entorno)
        String secretKey = "Sk/uXJSiwA8Ol2F59NnMBj9k7NYviJ06OOCz3DO7KU8ktqqHBnkt+EkEgJHu4133";

        // 🔹 Texto original a encriptar
        String plainText = "serverpass";

        // 🔧 Configurar encriptor
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        config.setPassword(secretKey);
        config.setAlgorithm("PBEWITHHMACSHA512ANDAES_256");
        config.setKeyObtentionIterations("100000");
        config.setPoolSize("1");
        config.setProviderName("SunJCE");
        config.setSaltGeneratorClassName("org.jasypt.salt.RandomSaltGenerator");
        config.setIvGeneratorClassName("org.jasypt.iv.RandomIvGenerator");
        config.setStringOutputType("base64");
        encryptor.setConfig(config);

        // 🔒 Encriptar
        String encrypted = encryptor.encrypt(plainText);
        System.out.println("🔒 Encriptado: ENC(" + encrypted + ")");

        // 🔓 Desencriptar
        String decrypted = encryptor.decrypt("1N0NhVhqf6Ip1ISH0JA8cTSVNJ6CnbSLd6LZHIS+n1vYpTG9fm6J7nn/h7NvQMLE");
        System.out.println("🔓 Desencriptado: " + decrypted);
    }



}
