package com.banred.ms_middleware_signcrypt.domain.mtls.service.impl;

import com.banred.ms_middleware_signcrypt.components.X509CertificateValidator;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.mtls.service.WebClientService;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.time.Duration;

@Service
public class WebClientServiceImpl implements WebClientService {

    private static final Logger logger = LoggerFactory.getLogger(WebClientServiceImpl.class);

    private final X509CertificateValidator certificateValidator;

    public WebClientServiceImpl(X509CertificateValidator certificateValidator) {
        this.certificateValidator = certificateValidator;
    }

    @Override
    public WebClient createWebClient(Institution institution) {
        try {
            // 1. Configurar KeyStore y TrustStore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(institution.getMtls().getKeystore())) {
                keyStore.load(fis, institution.getMtls().getKeystorePassword().toCharArray());
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, institution.getMtls().getKeystorePassword().toCharArray());
            certificateValidator.validateKeyStoreCertificates(keyStore, institution);

            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(institution.getMtls().getTruststore())) {
                trustStore.load(fis, institution.getMtls().getTruststorePassword().toCharArray());
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            certificateValidator.validateTrustStoreCertificates(trustStore, institution);

            // 2. Crear SslContext de Netty
            SslContext sslCtx = SslContextBuilder.forClient()
                    .sslProvider(SslProvider.JDK)
                    .keyManager(kmf)
                    .trustManager(tmf)
                    .build();

            // 3. Crear HttpClient con SSL
            HttpClient httpClient = HttpClient.create()
                    .secure(sslSpec -> sslSpec.sslContext(sslCtx))
                    .responseTimeout(Duration.ofMillis(institution.getTimeout()));

            // 4. Crear WebClient
            WebClient webClient = WebClient.builder()
                    .clientConnector(new ReactorClientHttpConnector(httpClient))
                    .baseUrl(institution.getEndpoint())
                    .build();

            logger.info("WebClient con MTLS creado para institución {}", institution.getId());
            return webClient;

        } catch (Exception e) {
            logger.error("Error creando WebClient para institución {}", institution.getId(), e);
            throw new RuntimeException("Error inicializando WebClient con MTLS", e);
        }
    }

    private String decrypt(String encryptedPassword) {
        // TODO: implementar desencriptación real
        return encryptedPassword;
    }
}
