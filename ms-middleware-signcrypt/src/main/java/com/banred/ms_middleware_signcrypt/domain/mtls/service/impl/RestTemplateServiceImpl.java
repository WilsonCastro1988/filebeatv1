package com.banred.ms_middleware_signcrypt.domain.mtls.service.impl;

import com.banred.ms_middleware_signcrypt.components.X509CertificateValidator;
import com.banred.ms_middleware_signcrypt.components.X509CertificateValidatorV2;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionService;
import com.banred.ms_middleware_signcrypt.domain.mtls.service.RestTemplateService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.KeyStore;
import java.util.Arrays;

@Service
public class RestTemplateServiceImpl implements RestTemplateService {

    private static final Logger logger = LoggerFactory.getLogger(RestTemplateServiceImpl.class);

    @Autowired
    private IInstitutionService iis;

    @Autowired
    private IInstitutionRedisService institutionRedisService;

    @Autowired
    private X509CertificateValidatorV2 certificateValidator;


    @Override
    public RestTemplate getRestTemplate(Institution institution) {
        logger.info("Creando RestTemplate para institución {}", institution.getId());
        try {
            RestTemplate restTemplate;
            SSLContext sslContext = configureSSLContext(institution);
            restTemplate = new RestTemplate(createRequestFactory(sslContext, institution.getTimeout()));
            logger.info("RestTemplate con MTLS -> institución {}", institution.getId());
            return restTemplate;
        } catch (Exception e) {
            logger.error("Error al crear RestTemplate para institución {}", institution.getId(), e);
            throw new RuntimeException("Error inicializando RestTemplates", e);
        }
    }

    private SSLContext configureSSLContext(Institution institution) {
        char[] keystorePassword = null;
        char[] truststorePassword = null;
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");

            // Cargar keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keystorePassword = decrypt(institution.getMtls().getKeystorePassword()).toCharArray();
            try (FileInputStream fis = new FileInputStream(institution.getMtls().getKeystore())) {
                keyStore.load(fis, keystorePassword);
            }


            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keystorePassword);

            // Cargar truststore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            truststorePassword = decrypt(institution.getMtls().getTruststorePassword()).toCharArray();
            try (FileInputStream fis = new FileInputStream(institution.getMtls().getTruststore())) {
                trustStore.load(fis, truststorePassword);
            }

            // Validar keystore
            certificateValidator.validateKeyStoreCertificates(keyStore, trustStore,institution);


            // Validar truststore
            certificateValidator.validateTrustStoreCertificates(trustStore, institution);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return sslContext;

        } catch (Exception e) {
            logger.error("Error configurando SSLContext para institución {}", institution.getId(), e);
            throw new RuntimeException("Error configurando SSLContext para institución " + institution.getId(), e);
        } finally {
            if (keystorePassword != null) Arrays.fill(keystorePassword, '\0');
            if (truststorePassword != null) Arrays.fill(truststorePassword, '\0');
        }
    }

    private ClientHttpRequestFactory createRequestFactory(SSLContext sslContext, int timeout) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                if (connection instanceof HttpsURLConnection) {
                    ((HttpsURLConnection) connection).setSSLSocketFactory(sslContext.getSocketFactory());
                }
                super.prepareConnection(connection, httpMethod);
            }
        };
        factory.setConnectTimeout(timeout);
        factory.setReadTimeout(timeout);
        return factory;
    }

    private String decrypt(String encryptedPassword) {
        // TODO: implementar desencriptación real
        return encryptedPassword;
    }
}
