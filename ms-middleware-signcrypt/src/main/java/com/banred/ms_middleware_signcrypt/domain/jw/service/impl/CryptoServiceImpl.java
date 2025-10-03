package com.banred.ms_middleware_signcrypt.domain.jw.service.impl;


import com.banred.ms_middleware_signcrypt.common.constant.TipoArgorithm;
import com.banred.ms_middleware_signcrypt.common.constant.TipoCanal;
import com.banred.ms_middleware_signcrypt.common.constant.TipoCertificado;
import com.banred.ms_middleware_signcrypt.common.util.Utilities;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.SecurityConfig;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import com.banred.ms_middleware_signcrypt.domain.jw.service.aes256.Aes256;
import com.banred.ms_middleware_signcrypt.domain.jw.service.aes256.IAes256;
import com.banred.ms_middleware_signcrypt.domain.jw.service.rsa.IRsa;
import com.banred.ms_middleware_signcrypt.domain.jw.service.rsa.Rsa;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import org.bouncycastle.crypto.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static com.banred.ms_middleware_signcrypt.common.util.Utilities.toPrivateKey;
import static com.banred.ms_middleware_signcrypt.common.util.Utilities.toPublicKey;


@Service
public class CryptoServiceImpl implements CryptoService {

    @Autowired
    private IInstitutionRedisService institutionRedisService;

    @Autowired
    private Aes256 aes256;

    @Autowired
    private Rsa rsa;

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoServiceImpl.class);

    @Override
    public String encryptData(String payload) throws Exception {
        if (payload == null || payload.isEmpty()) {
            throw new IllegalArgumentException("El payload no puede ser nulo o vacío");
        }
        Institution institution = institutionRedisService.getInstitution(payload);
        return encrypt(payload, institution);
    }


    @Override
    public String encrypt(String payload, Institution client) throws Exception {
        try {
            // 1) Obtener la clave pública RSA del cliente (proveedor)
            String pubKeyBase64 = rsa.getPublicKey(client.getId(), TipoCanal.IN.getValue(),
                    TipoCertificado.PROVEEDOR.getValue(), client.getJwe().getTruststore());
            PublicKey pub = toPublicKey(pubKeyBase64, TipoArgorithm.RSA.getValue());
            if (!(pub instanceof RSAPublicKey)) {
                throw new CryptoException("Clave pública no es RSA");
            }

            // 2) (Opcional) firmar payload con JWS antes de cifrar (si se requiere)
            // Si necesitas firmar: payload = sign(payload, ...);

            // 3) Construir JWE híbrido: ALG = RSA-OAEP-256, ENC = A256GCM
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                    .contentType("JWT") // o "text/plain" según sea
                    .build();

            JWEObject jwe = new JWEObject(header, new Payload(payload));

            // 4) Encriptar con RSA en el campo encrypted_key (híbrido)
            RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) pub);
            jwe.encrypt(encrypter);

            String serialized = jwe.serialize();
            // No loggear payload ni claves
            LOGGER.debug("JWE generado para institución {}", client.getId());
            return serialized;

        } catch (Exception e) {
            LOGGER.error("Error en encrypt", e);
            throw new CryptoException("Error al encriptar payload", e);
        }
    }

    @Override
    public String decrypt(String jweCompact, Institution institution) throws Exception {
        if (jweCompact == null || jweCompact.isEmpty()) {
            throw new IllegalArgumentException("El JWE compact no puede ser nulo o vacío");
        }
        if (institution == null) throw new IllegalArgumentException("institution es null");

        try {
            // 1) Cargar clave privada del keystore mediante tu servicio RSA
            String privateKeyBase64 = rsa.getPrivateKey(TipoCanal.IN.getValue(), institution.getId(),
                    TipoCertificado.PRIVATE.getValue(), institution.getJwe().getKeystore());
            PrivateKey privateKey = toPrivateKey(privateKeyBase64, TipoArgorithm.RSA.getValue());

            JWEObject jweObject = JWEObject.parse(jweCompact);

            // Validamos que el algoritmo sea el esperado (opcional)
            if (!JWEAlgorithm.RSA_OAEP_256.equals(jweObject.getHeader().getAlgorithm())) {
                LOGGER.warn("Algoritmo JWE inesperado: {}", jweObject.getHeader().getAlgorithm());
            }

            // 2) Desencriptar con RSADecrypter — Nimbus se encarga de CEK
            RSADecrypter decrypter = new RSADecrypter(privateKey);
            jweObject.decrypt(decrypter);

            String payload = jweObject.getPayload().toString();
            // Si era JWS firmado antes de cifrar, verificar aquí con verify(...)
            LOGGER.debug("JWE desencriptado para institución {}", institution.getId());
            return payload;

        } catch (JOSEException e) {
            LOGGER.error("Error JOSE al desencriptar", e);
            throw new CryptoException("Error JOSE al desencriptar JWE", e);
        } catch (Exception e) {
            LOGGER.error("Error al desencriptar JWE", e);
            throw new CryptoException("Error al desencriptar JWE", e);
        }
    }

    // -------------------------
    // JWS (Firma / Verify)
    // -------------------------

    @Override
    public String sign(String payload, SecurityConfig jwsConfig) throws Exception {
        if (payload == null) throw new IllegalArgumentException("payload null");
        try {
            String base64Priv = rsa.getPrivateKey(TipoCanal.IN.getValue(), null, TipoCertificado.PRIVATE.getValue(), jwsConfig.getKeystore());
            PrivateKey priv = toPrivateKey(base64Priv, TipoArgorithm.RSA.getValue());

            JWSAlgorithm jwsAlg = JWSAlgorithm.RS256; // o parse desde jwsConfig
            JWSObject jws = new JWSObject(new JWSHeader.Builder(jwsAlg).type(JOSEObjectType.JWT).build(),
                    new Payload(payload));

            JWSSigner signer = new RSASSASigner(priv);
            jws.sign(signer);
            LOGGER.debug("JWS generado (no logear contenido)");
            return jws.serialize();
        } catch (Exception e) {
            LOGGER.error("Error firmando JWS", e);
            throw new CryptoException("Error firmando JWS", e);
        }
    }

    @Override
    public boolean verify(String jwsCompact, SecurityConfig jwsConfig) throws Exception {
        if (jwsCompact == null) throw new IllegalArgumentException("jwsCompact null");
        try {
            String base64Pub = rsa.getPublicKey(TipoCanal.IN.getValue(), null, TipoCertificado.PUBLIC.getValue(), jwsConfig.getKeystore());
            PublicKey pub = toPublicKey(base64Pub, TipoArgorithm.RSA.getValue());

            JWSObject jws = JWSObject.parse(jwsCompact);
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) pub);
            boolean ok = jws.verify(verifier);
            LOGGER.debug("Verificación JWS: {}", ok);
            return ok;
        } catch (Exception e) {
            LOGGER.error("Error verificando JWS", e);
            throw new CryptoException("Error verificando JWS", e);
        }
    }
}
