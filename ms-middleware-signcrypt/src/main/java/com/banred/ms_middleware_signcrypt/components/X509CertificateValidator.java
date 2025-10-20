package com.banred.ms_middleware_signcrypt.components;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractError;
import com.banred.ms_middleware_signcrypt.common.exception.AbstractException;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class X509CertificateValidator {

    @Value("${microservice.parameters.RUTA_CRL}")
    private String rutaCRL;

    private static final Logger logger = LoggerFactory.getLogger(X509CertificateValidator.class);

    public X509CertificateValidator() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Valida los certificados de cliente contenidos en el keystore.
     */
    public void validateKeyStoreCertificates(KeyStore keyStore, KeyStore trustStore, Institution institution) throws KeyStoreException, CertificateException, NoSuchProviderException {
        String institutionId = institution.getId();
        Enumeration<String> aliases = keyStore.aliases();
        Set<String> serialNumbers = new HashSet<>(); // Para verificar unicidad de serial numbers

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

            if (cert == null) {
                throw new AbstractError("401", "No se encontró certificado para alias " + alias + " en institución " + institutionId, null);
            }

            validateCertificateValidity(cert, institutionId, alias);
            validateKeyUsage(cert, institutionId, alias);
            validateExtendedKeyUsage(cert, institutionId, alias);
            validateBasicConstraints(cert, institutionId, alias);
            validateSignatureAlgorithm(cert, institutionId, alias);
            validateSubjectDN(cert, institution, alias);
            validateSerialNumber(cert, serialNumbers, institutionId, alias);
            validateChain(cert, trustStore, institutionId, alias);
            validateCertificateWithCRL(cert, institutionId);
        }
    }

    private void validateCertificateValidity(X509Certificate cert, String institutionId, String alias) {
        try {
            cert.checkValidity();
            logger.info("Certificado válido en keystore, institución {}, alias {}, expira {}", institutionId, alias, cert.getNotAfter());
        } catch (CertificateNotYetValidException | CertificateExpiredException e) {
            throw new AbstractError("401", "Certificado no válido aún en keystore para institución " + institutionId + ", alias " + alias, null);
        }
    }

    private void validateKeyUsage(X509Certificate cert, String institutionId, String alias) {
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage == null || !keyUsage[0]) {
            throw new AbstractError("401", "Certificado no permite firma digital en institución " + institutionId + ", alias " + alias, null);
        }
    }

    private void validateExtendedKeyUsage(X509Certificate cert, String institutionId, String alias) {
        List<String> extendedKeyUsage;
        try {
            extendedKeyUsage = cert.getExtendedKeyUsage();
            if (extendedKeyUsage == null || !extendedKeyUsage.contains("1.3.6.1.5.5.7.3.2")) {
                throw new AbstractError("401", "Certificado no permite clientAuth en institución " + institutionId + ", alias " + alias, null);
            }
        } catch (CertificateParsingException e) {
            throw new AbstractError("401","Fallo en validateExtendedKeyUsage. Causa: " + e.getClass().getSimpleName() + " - " + e.getMessage(), "T",   e); // Encadenar la excepción original con contexto adicional
        }
      
    }

    private void validateBasicConstraints(X509Certificate cert, String institutionId, String alias) {
        if (cert.getBasicConstraints() >= 0) {
            throw new AbstractError("401", "Certificado de cliente no debe ser una CA en institución " + institutionId + ", alias " + alias, null);
        }
    }

    private void validateSignatureAlgorithm(X509Certificate cert, String institutionId, String alias){
        if (cert.getSigAlgName().contains("SHA1")) {
            throw new AbstractError("401", "Algoritmo de firma débil (SHA1) en certificado para institución " + institutionId + ", alias " + alias, null);
        }
        PublicKey publicKey = cert.getPublicKey();
        if (publicKey instanceof RSAPublicKey && ((RSAPublicKey) publicKey).getModulus().bitLength() < 2048) {
            throw new AbstractError("401", "Tamaño de clave RSA insuficiente (<2048 bits) para institución " + institutionId + ", alias " + alias, null);
        }
    }

    private void validateSubjectDN(X509Certificate cert, Institution institution, String alias) {
        String expectedCN = institution.getId();
        if (!cert.getSubjectX500Principal().getName().contains("CN=" + expectedCN)) {
            throw new AbstractError("401", "Subject CN no coincide con institución " + institution.getId() + ", alias " + alias, null);
        }
    }

    private void validateSerialNumber(X509Certificate cert, Set<String> serialNumbers, String institutionId, String alias) {
        String serial = cert.getSerialNumber().toString();
        if (!serialNumbers.add(serial)) {
            throw new AbstractError("401", "Serial number duplicado en keystore para institución " + institutionId + ", alias " + alias, null);
        }
    }

    /**
     * Valida los certificados del truststore (CAs).
     * Ahora lanza excepciones en lugar de solo advertencias.
     */
    public void validateTrustStoreCertificates(KeyStore trustStore, Institution institution) throws KeyStoreException, CertificateException, NoSuchProviderException {
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
            if (publicKey instanceof RSAPublicKey rsapublickey && rsapublickey.getModulus().bitLength() < 2048) {
                throw new AbstractError("401", "Tamaño de clave RSA insuficiente (<2048 bits) en CA para institución " + institutionId + ", alias " + alias, null);
            }

            // 4. Validar contra CRL (opcional para CAs, dependiendo de tu caso)
            validateCertificateWithCRL(caCert, institutionId);
        }
    }

    /**
     * Valida un certificado individual contra la CRL configurada.
     */
    private void validateCertificateWithCRL(X509Certificate cert, String institutionId) throws CertificateException, NoSuchProviderException {
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
        } catch (AbstractException | IOException | CRLException e) {
            throw new AbstractError("401","Fallo en validación de CRL para institución " + institutionId + ". Causa: " + e.getClass().getSimpleName() + " - " + e.getMessage(), "T",   e); // Encadenar la excepción original con contexto adicional

        }
    }

    /**
     * Valida la cadena de confianza del certificado contra el truststore.
     */
    private void validateChain(X509Certificate cert, KeyStore trustStore, String institutionId, String alias) {
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
        } catch (AbstractException  | NoSuchAlgorithmException | KeyStoreException | InvalidAlgorithmParameterException | CertificateException | CertPathValidatorException e) {
            throw new AbstractError("401","Fallo en validateChain para institución " + institutionId + ". Causa: " + e.getClass().getSimpleName() + " - " + e.getMessage(), "T",   e); // Encadenar la excepción original con contexto adicional
        }
    }
}
