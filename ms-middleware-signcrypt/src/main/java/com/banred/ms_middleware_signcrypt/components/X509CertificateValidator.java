package com.banred.ms_middleware_signcrypt.components;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

@Component
public class X509CertificateValidator {

    @Value("${microservice.parameters.RUTA_CRL}")
    private String rutaCRL;

    private static final Logger logger = LoggerFactory.getLogger(X509CertificateValidator.class);

    /**
     * Valida los certificados de cliente contenidos en el keystore.
     */
    public void validateKeyStoreCertificates(KeyStore keyStore, Institution institution) throws Exception {
        String institutionId = institution.getId();
        Enumeration<String> aliases = keyStore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

            if (cert != null) {
                // Vigencia
                cert.checkValidity();
                logger.info("Certificado válido en keystore, institución {}, alias {}, expira {}",
                        institutionId, alias, cert.getNotAfter());

                // KeyUsage: debe permitir firma digital
                boolean[] keyUsage = cert.getKeyUsage();
                if (keyUsage == null || !keyUsage[0]) {
                    throw new IllegalStateException("Certificado no permite firma digital en institución " + institutionId);
                }

                // ExtendedKeyUsage: debe permitir clientAuth
                List<String> extendedKeyUsage = cert.getExtendedKeyUsage();
                if (extendedKeyUsage == null || !extendedKeyUsage.contains("1.3.6.1.5.5.7.3.2")) {
                    throw new IllegalStateException("Certificado no permite clientAuth en institución " + institutionId);
                }

                // Validar contra CRL
                validateCertificateWithCRL(cert, institutionId);
            }
        }
    }

    /**
     * Valida los certificados del truststore (CAs).
     * No lanza excepción salvo casos críticos; se usa como advertencia.
     */
    public void validateTrustStoreCertificates(KeyStore trustStore, Institution institution) throws Exception {
        String institutionId = institution.getId();
        Enumeration<String> aliases = trustStore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate caCert = (X509Certificate) trustStore.getCertificate(alias);

            if (caCert != null) {
                try {
                    caCert.checkValidity();
                    logger.info("CA válida en truststore, institución {}, alias {}, expira {}",
                            institutionId, alias, caCert.getNotAfter());
                } catch (Exception e) {
                    logger.warn("CA inválida en truststore {}, alias {}: {}", institutionId, alias, e.getMessage());
                }

                if (caCert.getBasicConstraints() < 0) {
                    logger.warn("El certificado en truststore no es una CA: institución {}, alias {}", institutionId, alias);
                }
            }
        }
    }

    /**
     * Valida un certificado individual contra la CRL configurada.
     */
    private void validateCertificateWithCRL(X509Certificate cert, String institutionId) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        //CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream in = new FileInputStream(rutaCRL)) {
            X509CRL crl = (X509CRL) cf.generateCRL(in);

            logger.info("CRL cargada: issuer {}, próxima actualización {}",
                    crl.getIssuerX500Principal(), crl.getNextUpdate());

            if (crl.isRevoked(cert)) {
                logger.error("❌ Certificado revocado para institución {}, sujeto {}, serial {}",
                        institutionId, cert.getSubjectX500Principal(), cert.getSerialNumber());
                throw new IllegalStateException("Certificado revocado en CRL para institución " + institutionId);
            } else {
                logger.info("✅ Certificado no revocado para institución {}, sujeto {}",
                        institutionId, cert.getSubjectX500Principal());
            }
        }catch (Exception e){
            logger.error("❌ ERROR Certificado no revocado para institución {} ",
                    e);
        }
    }
}
