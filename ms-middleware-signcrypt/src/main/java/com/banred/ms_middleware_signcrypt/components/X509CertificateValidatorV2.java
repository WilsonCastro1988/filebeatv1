package com.banred.ms_middleware_signcrypt.components;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractError;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class X509CertificateValidatorV2 {

    @Value("${microservice.parameters.RUTA_CRL}")
    private String rutaCRL;

    private static final Logger logger = LoggerFactory.getLogger(X509CertificateValidatorV2.class);

    public X509CertificateValidatorV2() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Valida los certificados de cliente contenidos en el keystore.
     */
    public void validateKeyStoreCertificates(KeyStore keyStore, KeyStore trustStore, Institution institution) throws Exception {
        String institutionId = institution.getId();
        Enumeration<String> aliases = keyStore.aliases();
        Set<String> serialNumbers = new HashSet<>(); // Para verificar unicidad de serial numbers

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

            if (cert == null) {
                throw new AbstractError("401", "No se encontró certificado para alias " + alias + " en institución " + institutionId, null);
            }

            // 1. Vigencia
            try {
                cert.checkValidity();
                logger.info("Certificado válido en keystore, institución {}, alias {}, expira {}", institutionId, alias, cert.getNotAfter());
            } catch (CertificateExpiredException e) {
                throw new AbstractError("401", "Certificado expirado en keystore para institución " + institutionId + ", alias " + alias, null);
            } catch (CertificateNotYetValidException e) {
                throw new AbstractError("401", "Certificado no válido aún en keystore para institución " + institutionId + ", alias " + alias, null);
            }

            // 2. KeyUsage: debe permitir firma digital
            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage == null || !keyUsage[0]) {
                throw new AbstractError("401", "Certificado no permite firma digital en institución " + institutionId + ", alias " + alias, null);
            }

            // 3. ExtendedKeyUsage: debe permitir clientAuth
            List<String> extendedKeyUsage = cert.getExtendedKeyUsage();
            if (extendedKeyUsage == null || !extendedKeyUsage.contains("1.3.6.1.5.5.7.3.2")) {
                throw new AbstractError("401", "Certificado no permite clientAuth en institución " + institutionId + ", alias " + alias, null);
            }

            // 4. Basic Constraints: no debe ser CA
            if (cert.getBasicConstraints() >= 0) {
                throw new AbstractError("401", "Certificado de cliente no debe ser una CA en institución " + institutionId + ", alias " + alias, null);
            }

            // 5. Algoritmo y tamaño de clave
            if (cert.getSigAlgName().contains("SHA1")) {
                throw new AbstractError("401", "Algoritmo de firma débil (SHA1) en certificado para institución " + institutionId + ", alias " + alias, null);
            }
            PublicKey publicKey = cert.getPublicKey();
            if (publicKey instanceof RSAPublicKey && ((RSAPublicKey) publicKey).getModulus().bitLength() < 2048) {
                throw new AbstractError("401", "Tamaño de clave RSA insuficiente (<2048 bits) para institución " + institutionId + ", alias " + alias, null);
            }

            // 6. Subject DN matching
            String expectedCN = institution.getId();
            String certName = cert.getSubjectX500Principal().getName();// Ajusta según tu lógica
            if (!cert.getSubjectX500Principal().getName().contains("CN=" + expectedCN)) {
                throw new AbstractError("401", "Subject CN no coincide con institución " + institutionId + ", alias " + alias, null);
            }

            // 7. Unicidad de serial number
            String serial = cert.getSerialNumber().toString();
            if (!serialNumbers.add(serial)) {
                throw new AbstractError("401", "Serial number duplicado en keystore para institución " + institutionId + ", alias " + alias, null);
            }

            // 8. Validar cadena de confianza (usa trustStore)
            validateChain(cert, trustStore, institutionId, alias);

            // 9. Validar contra CRL
            validateCertificateWithCRL(cert, institutionId);
        }
    }

    /**
     * Valida los certificados del truststore (CAs).
     * Ahora lanza excepciones en lugar de solo advertencias.
     */
    public void validateTrustStoreCertificates(KeyStore trustStore, Institution institution) throws Exception {
        String institutionId = institution.getId();
        Enumeration<String> aliases = trustStore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate caCert = (X509Certificate) trustStore.getCertificate(alias);

            if (caCert == null) {
                throw new AbstractError("401", "No se encontró certificado CA para alias " + alias + " en truststore de institución " + institutionId, null);
            }

            // 1. Vigencia
            try {
                caCert.checkValidity();
                logger.info("CA válida en truststore, institución {}, alias {}, expira {}", institutionId, alias, caCert.getNotAfter());
            } catch (Exception e) {
                throw new AbstractError("401", "CA inválida en truststore para institución " + institutionId + ", alias " + alias + ": " + e.getMessage(), null);
            }

            // 2. Basic Constraints: debe ser CA
            if (caCert.getBasicConstraints() < 0) {
                throw new AbstractError("401", "Certificado en truststore no es una CA para institución " + institutionId + ", alias " + alias, null);
            }

            // 3. Algoritmo y tamaño de clave
            if (caCert.getSigAlgName().contains("SHA1")) {
                throw new AbstractError("401", "Algoritmo de firma débil (SHA1) en CA para institución " + institutionId + ", alias " + alias, null);
            }
            PublicKey publicKey = caCert.getPublicKey();
            if (publicKey instanceof RSAPublicKey && ((RSAPublicKey) publicKey).getModulus().bitLength() < 2048) {
                throw new AbstractError("401", "Tamaño de clave RSA insuficiente (<2048 bits) en CA para institución " + institutionId + ", alias " + alias, null);
            }

            // 4. Validar contra CRL (opcional para CAs, dependiendo de tu caso)
            validateCertificateWithCRL(caCert, institutionId);
        }
    }

    /**
     * Valida un certificado individual contra la CRL configurada.
     */
    private void validateCertificateWithCRL(X509Certificate cert, String institutionId) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        try (InputStream in = new FileInputStream(rutaCRL)) {
            X509CRL crl = (X509CRL) cf.generateCRL(in);
            logger.info("CRL cargada: issuer {}, próxima actualización {}", crl.getIssuerX500Principal(), crl.getNextUpdate());

            if (crl.isRevoked(cert)) {
                logger.error("❌ Certificado revocado para institución {}, sujeto {}, serial {}", institutionId, cert.getSubjectX500Principal(), cert.getSerialNumber());
                throw new AbstractError("401", "Certificado revocado en CRL para institución " + institutionId, null);
            } else {
                logger.info("✅ Certificado no revocado para institución {}, sujeto {}", institutionId, cert.getSubjectX500Principal());
            }
        } catch (Exception e) {
            logger.error("Error cargando o validando CRL para institución {}", institutionId, e);
            throw new AbstractError("401", "Fallo en validación de CRL para institución " + institutionId + ": " + e.getMessage(), null);
        }
    }

    /**
     * Valida la cadena de confianza del certificado contra el truststore.
     */
    private void validateChain(X509Certificate cert, KeyStore trustStore, String institutionId, String alias) throws Exception {
        try {
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            Enumeration<String> aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                X509Certificate caCert = (X509Certificate) trustStore.getCertificate(aliases.nextElement());
                if (caCert != null) {
                    trustAnchors.add(new TrustAnchor(caCert, null));
                }
            }
            if (trustAnchors.isEmpty()) {
                throw new AbstractError("401", "No hay CAs confiables en truststore para institución " + institutionId, null);
            }
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false); // CRL ya validado por separado
            CertPath certPath = CertificateFactory.getInstance("X.509").generateCertPath(List.of(cert));
            validator.validate(certPath, params);
            logger.info("Cadena de confianza válida para certificado en institución {}, alias {}", institutionId, alias);
        } catch (Exception e) {
            throw new AbstractError("401", "Fallo en validación de cadena de confianza para institución " + institutionId + ", alias " + alias + ": " + e.getMessage(), null);
        }
    }
}
