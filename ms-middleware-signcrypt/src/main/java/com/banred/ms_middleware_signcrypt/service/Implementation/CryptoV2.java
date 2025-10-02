package com.banred.ms_middleware_signcrypt.service.Implementation;

import com.banred.ms_middleware_signcrypt.model.Institution;
import com.banred.ms_middleware_signcrypt.model.SecurityConfig;
import com.banred.ms_middleware_signcrypt.service.CryptoService;
import com.banred.ms_middleware_signcrypt.service.CryptoService2;
import com.banred.ms_middleware_signcrypt.service.IInstitutionRedisService;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.DirectDecrypter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

@Service
public class CryptoV2 implements CryptoService2 {

    @Autowired
    private IInstitutionRedisService institutionRedisService;

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoServiceImpl.class);
    private static final int AES_KEY_SIZE = 256; // Tamaño de clave AES en bits
    private static final JWEAlgorithm JWE_ALG = JWEAlgorithm.RSA_OAEP_256;
    private static final EncryptionMethod ENC_METHOD = EncryptionMethod.A256GCM;
    private static final JWSAlgorithm DEFAULT_JWS_ALG = JWSAlgorithm.RS256;

    // ======================
    //  JWE (Encriptación Híbrida: AES + RSA)
    // ======================

    @Override
    public String encryptData(String payload) throws Exception {
        if (payload == null || payload.isEmpty()) {
            throw new IllegalArgumentException("El payload no puede ser nulo o vacío");
        }
        Institution institution = institutionRedisService.getInstitution(payload);
        return encrypt(payload, institution.getJwe(), true);
    }

    @Override
    public String encrypt(String payload, SecurityConfig jweConfig) throws Exception {
        return encrypt(payload, jweConfig, true);
    }

    public String encrypt(String payload, SecurityConfig jweConfig, boolean signPayload) throws Exception {
        // Cargar clave pública RSA y validar certificado
        X509Certificate certificate = loadCertificate(jweConfig);
        PublicKey publicKey = certificate.getPublicKey();
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("La clave pública debe ser RSA");
        }

        // Validar la cadena de certificados
        validateCertificateChain(certificate, jweConfig);

        // Firmar el payload con JWS si se solicita
        String signedPayload = payload;
        if (signPayload) {
            signedPayload = sign(payload, jweConfig);
            LOGGER.debug("Payload firmado (JWS): {}", signedPayload);
        }

        // Construir header JWE
        JWEHeader header = new JWEHeader.Builder(JWE_ALG, ENC_METHOD)
                .type(JOSEObjectType.JWT)
                .compressionAlgorithm(CompressionAlgorithm.DEF) // Soporte para compresión
                .build();

        // Crear objeto JWE
        JWEObject jweObject = new JWEObject(
                header,
                new Payload(signedPayload)
        );

        try {
            // Encriptar usando RSA-OAEP-256 y AES-256-GCM
            RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) publicKey);
            jweObject.encrypt(encrypter);
            String jwe = jweObject.serialize();
            LOGGER.debug("JWE generado: {}", jwe);
            return jwe;
        } catch (JOSEException e) {
            LOGGER.error("Error al encriptar JWE", e);
            throw new IllegalStateException("Error al encriptar el payload con JWE", e);
        }
    }

    @Override
    public String decrypt(String jweCompact, SecurityConfig jweConfig) throws Exception {
        return decrypt(jweCompact, jweConfig, true);
    }

    public String decrypt(String jweCompact, SecurityConfig jweConfig, boolean verifySignedPayload) throws Exception {
        // Validar entrada
        if (jweCompact == null || jweCompact.isEmpty()) {
            throw new IllegalArgumentException("El JWE compact no puede ser nulo o vacío");
        }
        LOGGER.debug("JWE recibido: {}", jweCompact);

        // Parsear JWE
        JWEObject jweObject;
        try {
            jweObject = JWEObject.parse(jweCompact);
        } catch (java.text.ParseException e) {
            throw new IllegalArgumentException("Formato JWE inválido", e);
        }

        // Validar algoritmo y método de encriptación
        JWEHeader header = jweObject.getHeader();
        if (!header.getAlgorithm().equals(JWE_ALG)) {
            throw new IllegalArgumentException("Algoritmo JWE no soportado: " + header.getAlgorithm());
        }
        if (!header.getEncryptionMethod().equals(ENC_METHOD)) {
            throw new IllegalArgumentException("Método de encriptación no soportado: " + header.getEncryptionMethod());
        }

        // Cargar clave privada RSA y validar certificado
        X509Certificate certificate = loadCertificate(jweConfig);
        PrivateKey privateKey = loadPrivateKey(jweConfig);
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new IllegalArgumentException("La clave privada debe ser RSA");
        }

        // Validar la cadena de certificados
        validateCertificateChain(certificate, jweConfig);

        // Desencriptar JWE
        try {
            jweObject.decrypt(new DirectDecrypter(generateSecretKeyFromCek(jweObject.getEncryptedKey().decode(), privateKey)));
        } catch (JOSEException e) {
            LOGGER.error("Error al desencriptar JWE", e);
            throw new IllegalStateException("Error al desencriptar el payload con JWE", e);
        }

        // Obtener el payload desencriptado
        String decryptedPayload = jweObject.getPayload().toString();
        LOGGER.debug("Payload desencriptado: {}", decryptedPayload);

        // Verificar la firma JWS si se solicitó
        if (verifySignedPayload) {
            try {
                JWSObject jwsObject = JWSObject.parse(decryptedPayload);
                if (!verify(jwsObject.serialize(), jweConfig)) {
                    throw new IllegalStateException("La firma JWS del payload desencriptado no es válida");
                }
                decryptedPayload = jwsObject.getPayload().toString();
                LOGGER.debug("JWS verificado, payload final: {}", decryptedPayload);
            } catch (java.text.ParseException e) {
                throw new IllegalArgumentException("El payload desencriptado no es un JWS válido", e);
            }
        }

        return decryptedPayload;
    }

    // Método auxiliar para generar SecretKey desde encrypted_key
    private SecretKey generateSecretKeyFromCek(byte[] encryptedCek, PrivateKey privateKey) throws Exception {
        try {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] cekBytes = rsaCipher.doFinal(encryptedCek);
            return new SecretKeySpec(cekBytes, "AES");
        } catch (Exception e) {
            throw new IllegalStateException("Error al desencriptar la CEK", e);
        } finally {
            if (encryptedCek != null) {
                Arrays.fill(encryptedCek, (byte) 0);
            }
        }
    }

    // ======================
    //  JWS (Firma digital)
    // ======================

    @Override
    public String sign(String payload, SecurityConfig jwsConfig) throws Exception {
        // Cargar clave privada y validar certificado
        X509Certificate certificate = loadCertificate(jwsConfig);
        PrivateKey privateKey = loadPrivateKey(jwsConfig);

        KeyStore keyStore = loadKeyStore(jwsConfig);
        String alias = keyStore.aliases().nextElement();


        // Validar que el certificado permita firmas digitales
        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage == null || !keyUsage[0]) { // digitalSignature
            throw new IllegalArgumentException("Certificado no permite firma digital para alias: " + alias);
        }

        // Validar la cadena de certificados
        validateCertificateChain(certificate, jwsConfig);

        // Determinar algoritmo JWS desde la configuración

        // Crear JWS
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(DEFAULT_JWS_ALG)
                        .type(JOSEObjectType.JWT)
                        .build(),
                new Payload(payload)
        );

        try {
            JWSSigner signer = new RSASSASigner(privateKey);
            jwsObject.sign(signer);
            String jws = jwsObject.serialize();
            LOGGER.debug("JWS generado: {}", jws);
            return jws;
        } catch (JOSEException e) {
            LOGGER.error("Error al firmar JWS", e);
            throw new IllegalStateException("Error al firmar el payload con JWS", e);
        }
    }

    @Override
    public boolean verify(String jwsCompact, SecurityConfig jwsConfig) throws Exception {
        // Cargar clave pública y validar certificado
        X509Certificate certificate = loadCertificate(jwsConfig);
        PublicKey publicKey = certificate.getPublicKey();
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("La clave pública debe ser RSA");
        }
        KeyStore keyStore = loadKeyStore(jwsConfig);
        String alias = keyStore.aliases().nextElement();
        // Validar que el certificado permita verificación de firmas
        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage == null || !keyUsage[0]) { // digitalSignature
            throw new IllegalArgumentException("Certificado no permite verificación de firma digital para alias: " + alias);
        }

        // Validar la cadena de certificados
        validateCertificateChain(certificate, jwsConfig);

        // Parsear JWS
        JWSObject jwsObject;
        try {
            jwsObject = JWSObject.parse(jwsCompact);
        } catch (java.text.ParseException e) {
            LOGGER.error("Formato JWS inválido", e);
            throw new IllegalArgumentException("Formato JWS inválido", e);
        }



        // Validar algoritmo JWS
        if (!jwsObject.getHeader().getAlgorithm().equals(DEFAULT_JWS_ALG)) {
            throw new IllegalArgumentException("Algoritmo JWS no soportado: " + jwsObject.getHeader().getAlgorithm());
        }

        // Verificar firma
        try {
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            boolean verified = jwsObject.verify(verifier);
            LOGGER.debug("Verificación JWS: {}", verified);
            return verified;
        } catch (JOSEException e) {
            LOGGER.error("Error al verificar JWS", e);
            throw new IllegalStateException("Error al verificar la firma JWS", e);
        }
    }

    // Método para firmar un JWE completo
    public String signJWE(String jweCompact, SecurityConfig jwsConfig) throws Exception {
        return sign(jweCompact, jwsConfig);
    }

    public boolean verifyJWE(String jwsCompact, SecurityConfig jwsConfig) throws Exception {
        return verify(jwsCompact, jwsConfig);
    }

    // ======================
    //  Utilidades de claves
    // ======================

    public SecretKey generateSecretKeyAES256() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private KeyStore loadKeyStore(SecurityConfig config) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] password = config.getKeystorePassword().toCharArray();
        try (FileInputStream fis = new FileInputStream(config.getKeystore())) {
            keyStore.load(fis, password);
            return keyStore;
        } finally {
            Arrays.fill(password, (char) 0); // Limpiar password
        }
    }

    public X509Certificate loadCertificate(SecurityConfig config) throws Exception {
        KeyStore keyStore = loadKeyStore(config);
        String alias = keyStore.aliases().nextElement();
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        if (cert == null) {
            throw new IllegalArgumentException("Certificado no encontrado para alias: " + alias);
        }
        try {
            cert.checkValidity();
            LOGGER.debug("Certificado válido para alias: {}", alias);
        } catch (Exception e) {
            LOGGER.error("Certificado no válido para alias: {}", alias, e);
            throw new IllegalArgumentException("Certificado expirado o no válido: " + alias, e);
        }
        return cert;
    }

    public PrivateKey loadPrivateKey(SecurityConfig config) throws Exception {
        KeyStore keyStore = loadKeyStore(config);
        String alias = keyStore.aliases().nextElement();
        char[] password = config.getKeystorePassword().toCharArray();
        try {
            PrivateKey key = (PrivateKey) keyStore.getKey(alias, password);
            if (key == null) {
                throw new IllegalArgumentException("Clave privada no encontrada para alias: " + alias);
            }
            return key;
        } finally {
            Arrays.fill(password, (char) 0); // Limpiar password
        }
    }

    private void validateCertificateChain(X509Certificate cert, SecurityConfig config) throws Exception {
        KeyStore keyStore = loadKeyStore(config);
        CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
        PKIXParameters params = new PKIXParameters(keyStore);
        params.setRevocationEnabled(false); // Deshabilitar CRL por ahora
        String alias = keyStore.aliases().nextElement();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certList = Collections.singletonList(cert);
        CertPath certPath = cf.generateCertPath(certList);

        try {
            certPathValidator.validate(certPath, params);
            LOGGER.info("Cadena de certificados válida para alias: {}", alias);
        } catch (CertPathValidatorException e) {
            LOGGER.error("Error validando cadena de certificados para alias: {}, error: {}", alias, e.getMessage());
            throw new IllegalStateException("Error validando cadena de certificados para alias: " + alias, e);
        }
    }

    // ======================
    //  Extra: exportar/decodificar clave AES a Base64
    // ======================

    public String encodeSecretKey(SecretKey secretKey) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(secretKey.getEncoded());
    }

    public SecretKey decodeSecretKey(String base64Key) {
        byte[] decoded = Base64.getUrlDecoder().decode(base64Key);
        return new SecretKeySpec(decoded, 0, decoded.length, "AES");
    }
}
