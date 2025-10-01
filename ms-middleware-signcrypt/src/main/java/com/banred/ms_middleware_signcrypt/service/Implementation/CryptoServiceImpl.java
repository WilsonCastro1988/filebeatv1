package com.banred.ms_middleware_signcrypt.service.Implementation;

import com.banred.ms_middleware_signcrypt.model.Institution;
import com.banred.ms_middleware_signcrypt.model.SecurityConfig;
import com.banred.ms_middleware_signcrypt.service.CryptoService;
import com.banred.ms_middleware_signcrypt.service.IInstitutionRedisService;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;


@Service
public class CryptoServiceImpl implements CryptoService {

    @Autowired
    private IInstitutionRedisService institutionRedisService;

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoServiceImpl.class);
    private static final int GCM_IV_LENGTH = 12; // 96 bits, recomendado para GCM
    private static final int GCM_TAG_LENGTH = 128; // Tag de autenticación de 128 bits
    private static final int GCM_TAG_LENGTH_BYTES = GCM_TAG_LENGTH / 8; // 16 bytes

    // ======================
    //  JWE (Encriptación Híbrida: AES + RSA)
    // ======================

    @Override
    public String encryptData(String payload) throws Exception {
        if (payload == null || payload.isEmpty()) {
            throw new IllegalArgumentException("El payload no puede ser nulo o vacío");
        }
        Institution institution = institutionRedisService.getInstitution(payload);
        return encrypt(payload, institution.getJwe());
    }

    @Override
    public String encrypt(String payload, SecurityConfig jweConfig) throws Exception {
        // Cargar clave pública RSA desde el certificado
        PublicKey publicKey = loadCertificate(jweConfig).getPublicKey();
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("La clave pública debe ser RSA");
        }

        // Generar clave AES-256 temporal (CEK)
        SecretKey cek = generateSecretKeyAES256();

        try {
            // Convertir payload a bytes y validar
            byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
            if (payloadBytes.length == 0) {
                throw new IllegalArgumentException("Los bytes del payload están vacíos");
            }
            LOGGER.debug("Payload: {}", payload);
            LOGGER.debug("Payload bytes length: {}", payloadBytes.length);

            // Generar IV
            byte[] iv = generateIv();
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            // Encriptar el payload con AES-256-GCM
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            aesCipher.init(Cipher.ENCRYPT_MODE, cek, gcmSpec);
            byte[] ciphertext;
            try {
                ciphertext = aesCipher.doFinal(payloadBytes);
            } catch (Exception e) {
                throw new IllegalStateException("Error al encriptar el payload con AES-GCM", e);
            }

            // Concatenar IV y ciphertext
            byte[] encryptedPayload = concatenateIvAndCiphertext(iv, ciphertext);
            LOGGER.debug("encryptedPayload length: {}", encryptedPayload.length);

            // Validar tamaño del ciphertext
            if (encryptedPayload.length < GCM_IV_LENGTH + GCM_TAG_LENGTH_BYTES) {
                throw new IllegalStateException(
                        "Ciphertext generado demasiado corto: longitud=" + encryptedPayload.length);
            }

            String encodedEncryptedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedPayload);

            // Cifrar la CEK con RSA pública (usando OAEP para seguridad)
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedCek;
            try {
                encryptedCek = rsaCipher.doFinal(cek.getEncoded());
            } catch (Exception e) {
                throw new IllegalStateException("Error al encriptar la CEK con RSA", e);
            }

            // Codificar la CEK cifrada en Base64 URL-safe sin padding
            String encodedEncryptedCek = Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedCek);

            // Construir header JWE sin criticalParams
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                    .type(JOSEObjectType.JWT)
                    .customParam("x-key", encodedEncryptedCek)
                    .build();

            // Serializar manualmente el JWE (header.payload.)
            String headerEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(header.toString().getBytes(StandardCharsets.UTF_8));
            String jwe = headerEncoded + "." + encodedEncryptedPayload + ".";
            LOGGER.debug("JWE generado: {}", jwe);
            return jwe;
        } finally {
            // Limpiar CEK de memoria
            Arrays.fill(cek.getEncoded(), (byte) 0);
        }
    }

    @Override
    public String decrypt(String jweCompact, SecurityConfig jweConfig) throws Exception {
        // Validar entrada
        if (jweCompact == null || jweCompact.isEmpty()) {
            throw new IllegalArgumentException("El JWE compact no puede ser nulo o vacío");
        }
        LOGGER.debug("JWE recibido: {}", jweCompact);

        // Parsear manualmente el JWE (header.payload. o header.payload)
        String[] parts = jweCompact.split("\\.");
        if (parts.length < 2 || parts.length > 3) {
            throw new IllegalArgumentException(
                    "Formato JWE inválido: debe tener dos o tres partes (header.payload[.]), encontrado: " + parts.length);
        }
        if (parts.length == 3 && !parts[2].isEmpty()) {
            throw new IllegalArgumentException(
                    "Formato JWE inválido: la tercera parte debe estar vacía, encontrado: " + parts[2]);
        }

        // Decodificar el header
        JWEHeader header;
        try {
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            header = JWEHeader.parse(headerJson);
        } catch (Exception e) {
            throw new IllegalArgumentException("Header JWE inválido", e);
        }

        // Obtener el payload codificado
        String encodedEncryptedPayload = parts[1];
        if (encodedEncryptedPayload.isEmpty()) {
            throw new IllegalArgumentException("Payload JWE vacío");
        }

        // Cargar clave privada RSA
        PrivateKey privateKey = loadPrivateKey(jweConfig);
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new IllegalArgumentException("La clave privada debe ser RSA");
        }

        // Obtener x-key del header
        String encodedEncryptedCek = (String) header.getCustomParam("x-key");
        if (encodedEncryptedCek == null) {
            throw new IllegalArgumentException("Header JWE no contiene x-key");
        }

        // Decodificar Base64 URL-safe
        byte[] encryptedCek;
        try {
            encryptedCek = Base64.getUrlDecoder().decode(encodedEncryptedCek);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("x-key no es un Base64 válido", e);
        }

        // Descifrar la CEK con RSA privada
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] cekBytes;
        try {
            cekBytes = rsaCipher.doFinal(encryptedCek);
        } catch (Exception e) {
            throw new IllegalStateException("Error al desencriptar la CEK con RSA", e);
        }

        // Reconstruir la SecretKey AES
        SecretKey cek;
        try {
            cek = new javax.crypto.spec.SecretKeySpec(cekBytes, "AES");

            // Decodificar el payload encriptado
            byte[] encryptedPayload;
            try {
                encryptedPayload = Base64.getUrlDecoder().decode(encodedEncryptedPayload);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Payload no es un Base64 válido", e);
            }
            LOGGER.debug("encryptedPayload length: {}", encryptedPayload.length);

            // Validar tamaño mínimo del ciphertext (IV + datos + tag)
            if (encryptedPayload.length < GCM_IV_LENGTH + GCM_TAG_LENGTH_BYTES) {
                throw new IllegalArgumentException(
                        "Ciphertext demasiado corto para contener IV y tag: longitud=" + encryptedPayload.length);
            }

            // Extraer el IV y ciphertext
            byte[] iv = extractIv(encryptedPayload);
            byte[] ciphertext = extractCiphertext(encryptedPayload);
            LOGGER.debug("ciphertext length: {}", ciphertext.length);

            // Desencriptar el payload con AES-256-GCM
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            aesCipher.init(Cipher.DECRYPT_MODE, cek, gcmSpec);
            byte[] decryptedPayload;
            try {
                decryptedPayload = aesCipher.doFinal(ciphertext);
            } catch (Exception e) {
                throw new IllegalStateException("Error al desencriptar el payload con AES-GCM", e);
            }

            LOGGER.debug("JWE desencriptado: {}", new String(decryptedPayload, StandardCharsets.UTF_8));

            return new String(decryptedPayload, StandardCharsets.UTF_8);
        } finally {
            // Limpiar CEK de memoria
            Arrays.fill(cekBytes, (byte) 0);
        }
    }

    // ======================
    //  JWS (Firma digital)
    // ======================

    @Override
    public String sign(String payload, SecurityConfig jwsConfig) throws Exception {
        PrivateKey privateKey = loadPrivateKey(jwsConfig);

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .type(JOSEObjectType.JWT)
                        .build(),
                new Payload(payload)
        );

        JWSSigner signer = new RSASSASigner(privateKey);
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    @Override
    public boolean verify(String jwsCompact, SecurityConfig jwsConfig) throws Exception {
        PublicKey publicKey = loadCertificate(jwsConfig).getPublicKey();

        JWSObject jwsObject = JWSObject.parse(jwsCompact);

        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
        return jwsObject.verify(verifier);
    }

    // ======================
    //  Utilidades de claves
    // ======================

    public SecretKey generateSecretKeyAES256() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // 256 bits para AES-256
        return keyGenerator.generateKey();
    }

    private KeyStore loadKeyStore(SecurityConfig config) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] password = config.getKeystorePassword().toCharArray();
        try {
            keyStore.load(new FileInputStream(config.getKeystore()), password);
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
        cert.checkValidity(); // Validar expiración
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

    // ======================
    //  Extra: exportar/decodificar clave AES a Base64
    // ======================

    public String encodeSecretKey(SecretKey secretKey) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(secretKey.getEncoded());
    }

    public SecretKey decodeSecretKey(String base64Key) {
        byte[] decoded = Base64.getUrlDecoder().decode(base64Key);
        return new javax.crypto.spec.SecretKeySpec(decoded, 0, decoded.length, "AES");
    }

    // ======================
    //  Métodos auxiliares para manejo de IV y ciphertext
    // ======================

    private byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private byte[] concatenateIvAndCiphertext(byte[] iv, byte[] ciphertext) {
        byte[] encrypted = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(ciphertext, 0, encrypted, iv.length, ciphertext.length);
        return encrypted;
    }

    private byte[] extractIv(byte[] encryptedBytes) {
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(encryptedBytes, 0, iv, 0, GCM_IV_LENGTH);
        return iv;
    }

    private byte[] extractCiphertext(byte[] encryptedBytes) {
        int ciphertextLength = encryptedBytes.length - GCM_IV_LENGTH;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(encryptedBytes, GCM_IV_LENGTH, ciphertext, 0, ciphertextLength);
        return ciphertext;
    }
}
