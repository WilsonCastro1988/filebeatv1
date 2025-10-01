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
import java.security.cert.X509Certificate;
import java.util.Enumeration;

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
            RestTemplate restTemplate;
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
            logger.error("Error al crear RestTemplate para institución {}", institutionId, e);
            throw new RuntimeException("Error inicializando RestTemplates", e);
        }
    }

    private SSLContext configureSSLContext(Institution institution) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");

            // Cargar keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            String keystorePath = institution.getMtls().getKeystore();
            char[] keystorePassword = decrypt(institution.getMtls().getKeystorePassword()).toCharArray();
            try (FileInputStream fis = new FileInputStream(keystorePath)) {
                keyStore.load(fis, keystorePassword);
            }

            // Verificar certificados en el keystore
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                if (cert != null) {
                    try {
                        cert.checkValidity();
                        logger.info("Certificado válido en keystore, alias: {}, valido hasta: {}",
                                alias, cert.getNotAfter());
                    } catch (Exception e) {
                        logger.error("Certificado expirado o no válido en keystore, alias: {}, error: {}",
                                alias, e.getMessage());
                        throw new IllegalStateException("Certificado expirado o no válido en keystore para alias: " + alias, e);
                    }
                }
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keystorePassword);

            // Cargar truststore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            String truststorePath = institution.getMtls().getTruststore();
            char[] truststorePassword = decrypt(institution.getMtls().getTruststorePassword()).toCharArray();
            try (FileInputStream fis = new FileInputStream(truststorePath)) {
                trustStore.load(fis, truststorePassword);
            }

            // Verificar certificados en el truststore
            aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate cert = (X509Certificate) trustStore.getCertificate(alias);
                if (cert != null) {
                    try {
                        cert.checkValidity();
                        logger.info("Certificado válido en truststore, alias: {}, valido hasta: {}",
                                alias, cert.getNotAfter());
                    } catch (Exception e) {
                        logger.error("Certificado expirado o no válido en truststore, alias: {}, error: {}",
                                alias, e.getMessage());
                        throw new IllegalStateException("Certificado expirado o no válido en truststore para alias: " + alias, e);
                    }
                }
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return sslContext;

        } catch (Exception e) {
            logger.error("Error configurando SSLContext para institución {}", institution.getId(), e);
            throw new RuntimeException("Error configurando SSLContext para institución " + institution.getId(), e);
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
