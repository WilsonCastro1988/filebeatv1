package com.banred.ms_middleware_signcrypt.domain.jw.service.impl;

import com.banred.ms_middleware_signcrypt.common.constant.TipoArgorithm;
import com.banred.ms_middleware_signcrypt.common.constant.TipoCanal;
import com.banred.ms_middleware_signcrypt.common.constant.TipoCertificado;
import com.banred.ms_middleware_signcrypt.common.util.Utilities;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.SecurityConfig;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;

import static com.banred.ms_middleware_signcrypt.common.util.Utilities.toPrivateKey;
import static com.banred.ms_middleware_signcrypt.common.util.Utilities.toPublicKey;

@Service
public class CryptoServiceImpl implements CryptoService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoServiceImpl.class);
    private static final long MAX_AGE_SECONDS = 300; // 5 minutos

    @Autowired
    private IInstitutionRedisService institutionRedisService;

    @Autowired
    private Aes256 aes256;

    @Autowired
    private Rsa rsa;

    // ============================================================
    // 🔒 SECCIÓN JWE
    // ============================================================

    @Override
    public String encrypt(String payload, Institution client) throws Exception {
        if (payload == null || payload.trim().isEmpty()) {
            throw new IllegalArgumentException("Payload no puede estar vacío");
        }

        LOGGER.debug("Iniciando encriptación JWE para institución {}", client.getId());

        String llaveAES256 = aes256.generarLlave();
        SecretKey aesKey = Utilities.fromBase64(llaveAES256, TipoArgorithm.AES.getValue());

        String publicaRSA = rsa.getPublicKey(
                client.getId(),
                TipoCanal.IN.getValue(),
                TipoCertificado.PROVEEDOR.getValue(),
                client.getJwe().getTruststore()
        );

        String llaveSimetrica = rsa.cifrar(llaveAES256, publicaRSA);

        JWEHeader headerJw = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                .customParam("x-key", llaveSimetrica)
                .build();

        Payload payloadJw = new Payload(payload);
        JWEObject objectJw = new JWEObject(headerJw, payloadJw);
        objectJw.encrypt(new DirectEncrypter(aesKey));

        LOGGER.debug("✅ JWE generado correctamente");

        return objectJw.serialize();
    }

    @Override
    public String decrypt(String jweCompact, Institution institution) throws Exception {
        if (jweCompact == null || jweCompact.isEmpty()) {
            throw new IllegalArgumentException("El JWE compact no puede ser nulo o vacío");
        }

        LOGGER.debug("Desencriptando JWE para institución {}", institution.getId());

        JWEObject jweObject = JWEObject.parse(jweCompact);

        String llaveSimetrica = (String) jweObject.getHeader().toJSONObject().get("x-key");
        String base64PrivateKey = rsa.getPrivateKey(
                TipoCanal.IN.getValue(),
                institution.getId(),
                TipoCertificado.PRIVATE.getValue(),
                institution.getJwe().getKeystore()
        );

        String llaveAES256 = rsa.descifrar(llaveSimetrica, base64PrivateKey);
        SecretKey aesKey = Utilities.fromBase64(llaveAES256, TipoArgorithm.AES.getValue());

        jweObject.decrypt(new DirectDecrypter(aesKey));

        return jweObject.getPayload().toString();
    }

    // ============================================================
    // 🔏 SECCIÓN JWS
    // ============================================================

    @Override
    public String sign(String payload, SecurityConfig jwsConfig) throws Exception {
        if (payload == null || payload.trim().isEmpty()) {
            throw new IllegalArgumentException("Payload no puede estar vacío");
        }

        String base64PrivateKey = rsa.getPrivateKey(
                TipoCanal.IN.getValue(),
                null,
                TipoCertificado.PRIVATE.getValue(),
                jwsConfig.getKeystore()
        );

        PrivateKey privateKey = toPrivateKey(base64PrivateKey, TipoArgorithm.RSA.getValue());

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                new Payload(payload)
        );

        JWSSigner signer = new RSASSASigner(privateKey);
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    @Override
    public boolean verify(String jwsCompact, SecurityConfig jwsConfig) throws Exception {
        if (jwsCompact == null || jwsCompact.trim().isEmpty()) {
            throw new IllegalArgumentException("JWS compact no puede estar vacío");
        }

        String base64PublicKey = rsa.getPublicKey(
                TipoCanal.IN.getValue(),
                null,
                TipoCertificado.PUBLIC.getValue(),
                jwsConfig.getTruststore()
        );

        PublicKey publicKey = toPublicKey(base64PublicKey, TipoArgorithm.RSA.getValue());
        JWSObject jwsObject = JWSObject.parse(jwsCompact);

        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
        return jwsObject.verify(verifier);
    }

    // ============================================================
    // 🧠 LÓGICA AVANZADA: FIRMAR Y VERIFICAR CON METADATOS (digest + headers)
    // ============================================================

    public JWSResponse signWithHeaders(String payload, Institution institution) throws Exception {
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
    }

    public void verifyWithHeaders(String jwsCompact, String digestHeader, String signatureInput, Institution institution) throws Exception {
        validateTimestamps(signatureInput);
        validateKeyId(signatureInput, institution.getId());

        JWSObject jwsObject = JWSObject.parse(jwsCompact);
        String signedContent = jwsObject.getPayload().toString();

        String digestFromJws = signedContent.split("\n")[0].trim();
        if (!digestFromJws.equals(digestHeader)) {
            throw new SecurityException("Digest inválido: firmado=" + digestFromJws + ", recibido=" + digestHeader);
        }

        if (!this.verify(jwsCompact, institution.getJws())) {
            throw new SecurityException("Firma JWS inválida");
        }

        LOGGER.info("✅ Firma JWS verificada correctamente para institución {}", institution.getId());

    }

    // ============================================================
    // 🔍 MÉTODOS AUXILIARES
    // ============================================================

    private void validateTimestamps(String signatureInput) {
        long created = extractValue(signatureInput, "created=");
        long expires = extractValue(signatureInput, "expires=");
        long now = Instant.now().getEpochSecond();

        if (now < created || now > expires) {
            throw new SecurityException("Firma expirada o no válida");
        }
        if (expires - created > MAX_AGE_SECONDS) {
            throw new SecurityException("Validez de firma excede los 5 minutos");
        }
    }

    private void validateKeyId(String signatureInput, String expectedId) {
        if (!signatureInput.contains("keyid='" + expectedId + "'")) {
            throw new SecurityException("keyid no coincide con la institución esperada");
        }
    }

    private long extractValue(String input, String key) {
        String[] parts = input.split(key);
        if (parts.length > 1) {
            return Long.parseLong(parts[1].split(";")[0]);
        }
        throw new IllegalArgumentException(key + " no encontrado en Signature-Input");
    }
}
