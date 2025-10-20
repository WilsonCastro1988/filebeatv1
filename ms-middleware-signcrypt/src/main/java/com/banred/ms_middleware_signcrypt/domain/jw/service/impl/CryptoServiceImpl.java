package com.banred.ms_middleware_signcrypt.domain.jw.service.impl;

import com.banred.ms_middleware_signcrypt.common.constant.TipoArgorithm;
import com.banred.ms_middleware_signcrypt.common.constant.TipoCanal;
import com.banred.ms_middleware_signcrypt.common.constant.TipoCertificado;
import com.banred.ms_middleware_signcrypt.common.exception.AbstractException;
import com.banred.ms_middleware_signcrypt.common.util.Utilities;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.SecurityConfig;
import com.banred.ms_middleware_signcrypt.domain.jw.dto.JWSResponse;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import com.banred.ms_middleware_signcrypt.domain.jw.service.aes256.Aes256;
import com.banred.ms_middleware_signcrypt.domain.jw.service.rsa.Rsa;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;

import static com.banred.ms_middleware_signcrypt.common.exception.CryptoExceptionFactory.createCryptoException;
import static com.banred.ms_middleware_signcrypt.common.util.Utilities.toPrivateKey;
import static com.banred.ms_middleware_signcrypt.common.util.Utilities.toPublicKey;

@Service
public class CryptoServiceImpl implements CryptoService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoServiceImpl.class);
    private static final long MAX_AGE_SECONDS = 300; // 5 minutos

    // ============================================================
    // 🏷️ CÓDIGOS DE ERROR ESPECÍFICOS PARA CRIPTOGRAFÍA
    // ============================================================
    private static final String CRYPTO_ERROR_PREFIX = "CRYPTO_";
    public static final String JWE_PARSE_ERROR = CRYPTO_ERROR_PREFIX + "JWE_001";
    public static final String JWE_ENCRYPT_ERROR = CRYPTO_ERROR_PREFIX + "JWE_002";
    public static final String JWE_DECRYPT_ERROR = CRYPTO_ERROR_PREFIX + "JWE_003";
    public static final String JWS_SIGN_ERROR = CRYPTO_ERROR_PREFIX + "JWS_001";
    public static final String JWS_VERIFY_ERROR = CRYPTO_ERROR_PREFIX + "JWS_002";
    public static final String KEY_CONVERT_ERROR = CRYPTO_ERROR_PREFIX + "KEY_001";
    public static final String DIGEST_ERROR = CRYPTO_ERROR_PREFIX + "DIGEST_001";

    private final Aes256 aes256;


    private final Rsa rsa;

    public CryptoServiceImpl(Aes256 aes256, Rsa rsa) {
        this.aes256 = aes256;
        this.rsa = rsa;
    }


    // ============================================================
    // 🔒 SECCIÓN JWE
    // ============================================================

    @Override
    public String encrypt(String payload, Institution client) throws AbstractException {
        if (payload == null || payload.trim().isEmpty()) {
            throw new IllegalArgumentException("El payload para encriptar no puede ser nulo o vacío.");
        }
        LOGGER.debug("Iniciando encriptación JWE para institución {}", client.getId());

        try {
            String llaveAES256 = aes256.generarLlave();
            SecretKey aesKey = Utilities.fromBase64(llaveAES256, TipoArgorithm.AES.getValue());

            String publicaRSA = rsa.getPublicKey(client.getId(), TipoCanal.IN.getValue(), TipoCertificado.PROVEEDOR.getValue(), client.getJwe().getTruststore());
            String llaveSimetrica = rsa.cifrar(llaveAES256, publicaRSA);

            JWEHeader headerJw = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                    .customParam("x-key", llaveSimetrica)
                    .build();

            JWEObject objectJw = new JWEObject(headerJw, new Payload(payload));
            objectJw.encrypt(new DirectEncrypter(aesKey));

            LOGGER.debug("✅ JWE generado correctamente para la institución {}", client.getId());
            return objectJw.serialize();

        } catch (JOSEException e) {
            throw createCryptoException(e, JWE_ENCRYPT_ERROR, "encriptación JWE", client.getId());
        }
    }

    @Override
    public String decrypt(String jweCompact, Institution institution) throws AbstractException {
        if (jweCompact == null || jweCompact.isEmpty()) {
            throw new IllegalArgumentException("El JWE compact para desencriptar no puede ser nulo o vacío.");
        }
        LOGGER.debug("Desencriptando JWE para institución {}", institution.getId());

        try {
            JWEObject jweObject = JWEObject.parse(jweCompact);
            String llaveSimetrica = (String) jweObject.getHeader().toJSONObject().get("x-key");

            String base64PrivateKey = rsa.getPrivateKey(TipoCanal.IN.getValue(), institution.getId(), TipoCertificado.PRIVATE.getValue(), institution.getJwe().getKeystore());
            String llaveAES256 = rsa.descifrar(llaveSimetrica, base64PrivateKey);
            SecretKey aesKey = Utilities.fromBase64(llaveAES256, TipoArgorithm.AES.getValue());

            jweObject.decrypt(new DirectDecrypter(aesKey));
            return jweObject.getPayload().toString();

        } catch (ParseException e) {
            throw createCryptoException(e, JWE_PARSE_ERROR, "parseo de JWE", institution.getId());
        } catch (JOSEException e) {
            throw createCryptoException(e, JWE_DECRYPT_ERROR, "desencriptación JWE", institution.getId());
        }
    }

    // ============================================================
    // 🔏 SECCIÓN JWS
    // ============================================================

    @Override
    public String sign(String payload, SecurityConfig jwsConfig) throws AbstractException {
        if (payload == null || payload.trim().isEmpty()) {
            throw new IllegalArgumentException("El payload para firmar no puede ser nulo o vacío.");
        }
        String contextId = jwsConfig.getKeystore();

        try {
            String base64PrivateKey = rsa.getPrivateKey(TipoCanal.IN.getValue(), null, TipoCertificado.PRIVATE.getValue(), contextId);
            PrivateKey privateKey = toPrivateKey(base64PrivateKey, TipoArgorithm.RSA.getValue());

            JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(), new Payload(payload));
            JWSSigner signer = new RSASSASigner(privateKey);

            jwsObject.sign(signer);
            return jwsObject.serialize();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw createCryptoException(e, KEY_CONVERT_ERROR, "conversión de clave privada a formato RSA", contextId);
        } catch (JOSEException e) {
            throw createCryptoException(e, JWS_SIGN_ERROR, "firmado del payload JWS", contextId);
        }
    }

    @Override
    public boolean verify(String jwsCompact, SecurityConfig jwsConfig) throws AbstractException {
        if (jwsCompact == null || jwsCompact.trim().isEmpty()) {
            throw new IllegalArgumentException("El JWS compact para verificar no puede ser nulo o vacío.");
        }
        String contextId = jwsConfig.getTruststore();

        try {
            String base64PublicKey = rsa.getPublicKey(TipoCanal.IN.getValue(), null, TipoCertificado.PUBLIC.getValue(), contextId);
            PublicKey publicKey = toPublicKey(base64PublicKey, TipoArgorithm.RSA.getValue());

            JWSObject jwsObject = JWSObject.parse(jwsCompact);
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);

            return jwsObject.verify(verifier);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw createCryptoException(e, KEY_CONVERT_ERROR, "conversión de clave pública a formato RSA", contextId);
        } catch (ParseException e) {
            throw createCryptoException(e, JWS_VERIFY_ERROR, "parseo de JWS para verificación", contextId);
        } catch (JOSEException e) {
            throw createCryptoException(e, JWS_VERIFY_ERROR, "verificación de la firma JWS", contextId);
        }
    }

    // ============================================================
    // 🧠 LÓGICA AVANZADA: FIRMAR Y VERIFICAR CON METADATOS
    // ============================================================

    public JWSResponse signWithHeaders(String payload, Institution institution) throws AbstractException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String digestBase64 = Base64.getEncoder().encodeToString(digest.digest(payload.getBytes(StandardCharsets.UTF_8)));
            String digestHeader = "SHA-256=" + digestBase64;

            long created = Instant.now().getEpochSecond();
            long expires = created + MAX_AGE_SECONDS;

            String signatureInput = String.format(
                    "sig1=('digest');created=%d;keyid='%s';alg='rsa-sha256';expires=%d",
                    created, institution.getId(), expires
            );

            String toSign = digestHeader + "\n" + signatureInput;
            String jwsCompact = this.sign(toSign, institution.getJws());

            JWSObject jwsObject = JWSObject.parse(jwsCompact);
            String signature = Base64.getEncoder().encodeToString(jwsObject.getSignature().decode());
            String signatureHeader = "sig1=" + signature;

            return new JWSResponse(jwsCompact, digestHeader, signatureInput, signatureHeader);

        } catch (NoSuchAlgorithmException e) {
            throw createCryptoException(e, DIGEST_ERROR, "cálculo de digest SHA-256", institution.getId());
        } catch (ParseException e) {
            throw createCryptoException(e, JWS_SIGN_ERROR, "parseo de JWS recién firmado", institution.getId());
        }
    }

    public void verifyWithHeaders(String jwsCompact, String digestHeader, String signatureInput, Institution institution) throws AbstractException {
        validateTimestamps(signatureInput);
        validateKeyId(signatureInput, institution.getId());

        try {
            JWSObject jwsObject = JWSObject.parse(jwsCompact);
            String signedContent = jwsObject.getPayload().toString();

            String digestFromJws = signedContent.split("\n")[0].trim();
            if (!digestFromJws.equals(digestHeader)) {
                throw new SecurityException("Digest inválido: el digest firmado no coincide con el recibido.");
            }

            if (!this.verify(jwsCompact, institution.getJws())) {
                throw new SecurityException("Firma JWS inválida.");
            }

            LOGGER.info("✅ Firma JWS verificada correctamente para institución {}", institution.getId());

        } catch (ParseException e) {
            throw createCryptoException(e, JWS_VERIFY_ERROR, "parseo de JWS durante verificación con headers", institution.getId());
        }
        // SecurityException se deja propagar, ya que es un error de negocio, no técnico.
    }

    // ============================================================
    // 🔍 MÉTODOS AUXILIARES (Sin cambios)
    // ============================================================

    private void validateTimestamps(String signatureInput) {
        long created = extractValue(signatureInput, "created=");
        long expires = extractValue(signatureInput, "expires=");
        long now = Instant.now().getEpochSecond();

        if (now < created || now > expires) {
            throw new SecurityException("Firma expirada o no válida (fuera de la ventana de tiempo).");
        }
        if (expires - created > MAX_AGE_SECONDS) {
            throw new SecurityException("La validez de la firma excede el tiempo máximo permitido.");
        }
    }

    private void validateKeyId(String signatureInput, String expectedId) {
        if (!signatureInput.contains("keyid='" + expectedId + "'")) {
            throw new SecurityException("El 'keyid' de la firma no coincide con la institución esperada.");
        }
    }

    private long extractValue(String input, String key) {
        String[] parts = input.split(key);
        if (parts.length > 1) {
            return Long.parseLong(parts[1].split(";")[0]);
        }
        throw new IllegalArgumentException("'" + key + "' no encontrado en el Signature-Input.");
    }
}
