package com.banred.ms_middleware_signcrypt.service.Implementation;


import com.banred.ms_middleware_signcrypt.model.Institution;
import com.banred.ms_middleware_signcrypt.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.service.IInstitutionService;
import com.banred.ms_middleware_signcrypt.service.RestTemplateService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;


@Service
public class RestTemplateServiceImpl implements RestTemplateService {

    private static final Logger logger = LoggerFactory.getLogger(RestTemplateServiceImpl.class);

    @Autowired
    private IInstitutionService iis;

    @Autowired
    private IInstitutionRedisService institutionRedisService;


    @Override
    public RestTemplate getRestTemplate(String institutionId) {
        logger.info("Creando RestTemplate para institución {}", institutionId);
        try {
            Institution institution = institutionRedisService.getInstitution(institutionId);
            RestTemplate restTemplate = null;
            if (institution.getMtls() != null && institution.getMtls().isEnable()) {
                SSLContext sslContext = configureSSLContext(institution);
                restTemplate = new RestTemplate(createRequestFactory(sslContext, institution.getTimeout()));
                logger.info("RestTemplate con MTLS -> para institución {}", institutionId);
            } else {
                restTemplate = new RestTemplate(); // sin mTLS
                logger.info("RestTemplate sin MTLS -> para institución {}", institutionId);
            }

            return restTemplate;
        } catch (Exception e) {
            logger.error("Error al crear RestTemplate para institución {}", institutionId);
            throw new RuntimeException("Error inicializando RestTemplates", e);
        }
    }

    private SSLContext configureSSLContext(Institution institution) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(institution.getMtls().getKeystore()),
                    decrypt(institution.getMtls().getKeystorePassword()).toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, decrypt(institution.getMtls().getKeystorePassword()).toCharArray());

            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(institution.getMtls().getTruststore()),
                    decrypt(institution.getMtls().getTruststorePassword()).toCharArray());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            return sslContext;

        } catch (Exception e) {
            throw new RuntimeException("Error creando RestTemplate para institución " + institution.getId(), e);
        }
    }


    private ClientHttpRequestFactory createRequestFactory(SSLContext sslContext, int timeout) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(java.net.HttpURLConnection connection, String httpMethod) throws IOException {
                if (connection instanceof javax.net.ssl.HttpsURLConnection) {
                    ((javax.net.ssl.HttpsURLConnection) connection).setSSLSocketFactory(sslContext.getSocketFactory());
                }
                super.prepareConnection(connection, httpMethod);
            }
        };
        factory.setConnectTimeout(timeout);
        factory.setReadTimeout(timeout);
        return factory;
    }

    private String decrypt(String encryptedPassword) {
        // Aquí puedes implementar lógica real de desencriptación si aplica
        return encryptedPassword; // temporalmente sin desencriptar
    }
}

