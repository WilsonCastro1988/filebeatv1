package com.banred.ms_middleware_signcrypt.service.Implementation;

import com.banred.ms_middleware_signcrypt.components.X509CertificateValidator;
import com.banred.ms_middleware_signcrypt.model.Institution;
import com.banred.ms_middleware_signcrypt.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.service.IInstitutionService;
import com.banred.ms_middleware_signcrypt.service.RestTemplateService2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
public class RestTemplateServiceImpl2 implements RestTemplateService2 {

    private static final Logger logger = LoggerFactory.getLogger(RestTemplateServiceImpl2.class);

    @Autowired
    private IInstitutionService iis;

    @Autowired
    private IInstitutionRedisService institutionRedisService;

    @Autowired
    private X509CertificateValidator certificateValidator;



    @Override
    public RestTemplate getRestTemplate(String institutionId) {
        logger.info("Creando RestTemplate para institución {}", institutionId);
        try {
            Institution institution = institutionRedisService.getInstitution(institutionId);
            RestTemplate restTemplate;
            if (institution.getMtls() != null && institution.getMtls().isEnable()) {
                SSLContext sslContext = configureSSLContext(institution);
                restTemplate = new RestTemplate(createRequestFactory(sslContext, institution.getTimeout()));
                logger.info("RestTemplate con MTLS -> institución {}", institutionId);
            } else {
                restTemplate = new RestTemplate(); // sin mTLS
                logger.info("RestTemplate sin MTLS -> institución {}", institutionId);
            }
            return restTemplate;
        } catch (Exception e) {
            logger.error("Error al crear RestTemplate para institución {}", institutionId, e);
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

            // Validar keystore
            certificateValidator.validateKeyStoreCertificates(keyStore, institution);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keystorePassword);

            // Cargar truststore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            truststorePassword = decrypt(institution.getMtls().getTruststorePassword()).toCharArray();
            try (FileInputStream fis = new FileInputStream(institution.getMtls().getTruststore())) {
                trustStore.load(fis, truststorePassword);
            }

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
