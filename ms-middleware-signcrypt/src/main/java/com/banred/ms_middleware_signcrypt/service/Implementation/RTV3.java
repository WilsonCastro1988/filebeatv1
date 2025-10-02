package com.banred.ms_middleware_signcrypt.service.Implementation;

import com.banred.ms_middleware_signcrypt.model.Institution;
import com.banred.ms_middleware_signcrypt.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.service.IInstitutionService;
import com.banred.ms_middleware_signcrypt.service.RTV3Service;
import com.banred.ms_middleware_signcrypt.service.RestTemplateService2;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.security.KeyStore;
import java.security.Security;

import java.security.cert.*;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

@Service
public class RTV3 implements RTV3Service {

    private static final Logger logger = LoggerFactory.getLogger(RestTemplateServiceImpl.class);

    @Autowired
    private IInstitutionService iis;

    @Autowired
    private IInstitutionRedisService institutionRedisService;


    @Value("${microservice.parameters.RUTA_CRL}")
    private String rutaCRL;

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
        char[] keystorePassword = null;
        char[] truststorePassword = null;
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");

            // Cargar keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            String keystorePath = institution.getMtls().getKeystore();
            keystorePassword = decrypt(institution.getMtls().getKeystorePassword()).toCharArray();
            try (FileInputStream fis = new FileInputStream(keystorePath)) {
                keyStore.load(fis, keystorePassword);
            }

            // Validar certificados en el keystore
            validateCertificatesInKeyStore(keyStore, institution);


            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keystorePassword);

            // Cargar truststore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            String truststorePath = institution.getMtls().getTruststore();
            truststorePassword = decrypt(institution.getMtls().getTruststorePassword()).toCharArray();
            try (FileInputStream fis = new FileInputStream(truststorePath)) {
                trustStore.load(fis, truststorePassword);
            }

            // Validar certificados en el truststore
            validateCertificatesInTrustStore(trustStore, institution);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return sslContext;

        } catch (Exception e) {
            logger.error("Error configurando SSLContext para institución {}", institution.getId(), e);
            throw new RuntimeException("Error configurando SSLContext para institución " + institution.getId(), e);
        } finally {
            // Limpiar contraseñas de memoria
            if (keystorePassword != null) {
                Arrays.fill(keystorePassword, '\0');
            }
            if (truststorePassword != null) {
                Arrays.fill(truststorePassword, '\0');
            }
        }
    }

    private void validateCertificatesInKeyStore(KeyStore keyStore, Institution institution) throws Exception {
        String institutionId = institution.getId();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            if (cert != null) {
                try {
                    cert.checkValidity();
                    logger.info("Certificado válido en keystore, institución: {}, alias: {}, válido hasta: {}",
                            institutionId, alias, cert.getNotAfter());
                } catch (CertificateExpiredException e) {
                    logger.error("Certificado expirado en keystore, institución: {}, alias: {}, error: {}",
                            institutionId, alias, e.getMessage());
                    throw new IllegalStateException("Certificado expirado en keystore para institución: " + institutionId + ", alias: " + alias, e);
                } catch (CertificateNotYetValidException e) {
                    logger.error("Certificado no válido aún en keystore, institución: {}, alias: {}, error: {}",
                            institutionId, alias, e.getMessage());
                    throw new IllegalStateException("Certificado no válido aún en keystore para institución: " + institutionId + ", alias: " + alias, e);
                }

                // Verificar KeyUsage
                boolean[] keyUsage = cert.getKeyUsage();
                if (keyUsage == null || !keyUsage[0]) { // keyUsage[0] = digitalSignature
                    logger.error("Certificado no permite firma digital, institución: {}, alias: {}", institutionId, alias);
                    throw new IllegalStateException("Certificado no permite firma digital en keystore para institución: " + institutionId + ", alias: " + alias);
                }

                // Verificar ExtendedKeyUsage
                List<String> extendedKeyUsage = cert.getExtendedKeyUsage();
                if (extendedKeyUsage == null || !extendedKeyUsage.contains("1.3.6.1.5.5.7.3.2")) { // clientAuth
                    logger.error("Certificado no permite autenticación de cliente, institución: {}, alias: {}", institutionId, alias);
                    throw new IllegalStateException("Certificado no permite autenticación de cliente en keystore para institución: " + institutionId + ", alias: " + alias);
                }

                // Verificar la cadena de certificados
                //validateCertificateChain(cert, institution, alias);
            }
        }
    }

    private void validateCertificatesInTrustStore(KeyStore trustStore, Institution institution) throws Exception {
        String institutionId = institution.getId();
        Enumeration<String> aliases = trustStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate cert = (X509Certificate) trustStore.getCertificate(alias);
            if (cert != null) {
                // Verificar expiración
                try {
                    cert.checkValidity();
                    logger.info("Certificado válido en truststore, institución: {}, alias: {}, válido hasta: {}",
                            institutionId, alias, cert.getNotAfter());
                } catch (CertificateExpiredException e) {
                    logger.warn("Certificado expirado en truststore, institución: {}, alias: {}, error: {}",
                            institutionId, alias, e.getMessage());
                    // Nota: Las CAs en el truststore pueden estar expiradas si no son usadas directamente
                } catch (CertificateNotYetValidException e) {
                    logger.warn("Certificado no válido aún en truststore, institución: {}, alias: {}, error: {}",
                            institutionId, alias, e.getMessage());
                }

                // Verificar que sea una CA
                if (cert.getBasicConstraints() < 0) {
                    logger.warn("Certificado en truststore no es una CA, institución: {}, alias: {}", institutionId, alias);
                } else {
                    logger.info("Certificado en truststore es una CA, institución: {}, alias: {}, path limit: {}",
                            institutionId, alias, cert.getBasicConstraints());
                }

                // Verificar la cadena de certificados
                validateCertificateChain(cert, institution, alias);
            }
        }
    }

    public void validateCertificateChain(X509Certificate cert, Institution institution, String alias) throws Exception {
        String institutionId = institution.getId();

        // Cargar el truststore
        KeyStore trustStore = KeyStore.getInstance("JKS");
        String truststorePath = institution.getMtls().getTruststore();
        char[] truststorePassword = decrypt(institution.getMtls().getTruststorePassword()).toCharArray();

        try (FileInputStream fis = new FileInputStream(truststorePath)) {
            trustStore.load(fis, truststorePassword);
        }

        // Cargar la CRL desde archivo
        X509CRL crl;

        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory cf;
        try (InputStream in = new FileInputStream(rutaCRL)) {
            cf = CertificateFactory.getInstance("X.509", "BC");
            crl = (X509CRL) cf.generateCRL(in);
            logger.info("CRL loaded successfully: {}", crl);
        }



        // Crear CertStore con la CRL
        CertStore crlStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(Collections.singletonList(crl)));

        // Configurar parámetros de validación
        PKIXParameters params = new PKIXParameters(trustStore);
        params.setRevocationEnabled(true); // Habilitar validación de revocación


        try (InputStream in = new FileInputStream("C:/etc/tls/certs/ca/crl/crl.pem")) {
            cf = CertificateFactory.getInstance("X.509", "BC");
            crl = (X509CRL) cf.generateCRL(in);
            logger.info("CRL loaded successfully: {}", crl);

            crlStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(Collections.singletonList(crl)));

            params = new PKIXParameters(trustStore);
            params.addCertStore(crlStore);
        }



        //params.addCertStore(crlStore); // Agregar la CRL al CertStore

        // Crear la cadena de certificados
        List<X509Certificate> certList = new java.util.ArrayList<>(Collections.singletonList(cert));

        // Filtrar el certificado raíz (si está presente)
        //certList.removeIf(c -> c.getIssuerX500Principal().equals(c.getSubjectX500Principal()));

        CertPath certPath = cf.generateCertPath(certList);

        // Validar la cadena
        CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
        try {
            // Obtener el número de serie del certificado en formato hexadecimal
            BigInteger certSerial = cert.getSerialNumber();
            String certSerialHex = certSerial.toString(16).toUpperCase();


            // Iterar sobre los certificados revocados en la CRL
            crl.getRevokedCertificates().forEach(revokedCert -> {
                BigInteger revokedSerial = revokedCert.getSerialNumber();
                String revokedSerialHex = revokedSerial.toString(16).toUpperCase();

                if (certSerialHex.equals(revokedSerialHex)) {
                    System.out.println("El certificado está revocado.");
                }
            });

            certPathValidator.validate(certPath, params);
            logger.info("Cadena de certificados válida para institución: {}, alias: {}", institutionId, alias);
        } catch (CertPathValidatorException e) {
            logger.error("El certificado está revocado o no es válido: {}", e.getMessage());
            throw new IllegalStateException("Error validando cadena de certificados para institución: " + institutionId + ", alias: " + alias, e);
        } catch (Exception e) {
            logger.error("Error general durante la validación de certificados: {}", e.getMessage(), e);
            throw new IllegalStateException("Error general durante la validación de certificados para institución: " + institutionId + ", alias: " + alias, e);
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
        // Aquí puedes implementar lógica real de desencriptación si aplica
        return encryptedPassword; // temporalmente sin desencriptar
    }
}
