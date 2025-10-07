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
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
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
    public String encrypt(String payload, Institution client) throws Exception {
        try {
            if (payload == null || payload.trim().isEmpty()) {
                throw new IllegalArgumentException("Payload no puede estar vacío");
            }
            LOGGER.debug("Iniciando encriptación JWE para payload: {}", payload);

            String llaveAES256 = aes256.generarLlave();
            SecretKey aesKey = Utilities.fromBase64(llaveAES256, TipoArgorithm.AES.getValue());

            //String encryptedPayload = aes256.cifrar(payload, llaveAES256);

            String publicaRSA = rsa.getPublicKey(client.getId(), TipoCanal.IN.getValue(), TipoCertificado.PROVEEDOR.getValue(), client.getJwe().getTruststore());
            String llaveSimetrica = rsa.cifrar(llaveAES256, publicaRSA);

            JWEHeader headerJw = new JWEHeader
                    .Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                    .customParam("x-key", llaveSimetrica)
                    .build();

            Payload payloadJw = new Payload(payload);
            JWEObject objectJw = new JWEObject(headerJw, payloadJw);
            objectJw.encrypt(new DirectEncrypter(aesKey));

            LOGGER.debug("JWE generado: {}", objectJw.serialize().concat("::").concat(llaveSimetrica));

            //return objectJw.serialize().concat("::").concat(llaveSimetrica);
            return objectJw.serialize();
        } catch (Exception e) {
            LOGGER.debug("ERROR JWE generado: {}", e);
            throw new IllegalArgumentException("Header JWE inválido", e);
        }
    }

    @Override
    public String decrypt(String jweCompact, Institution institution) throws Exception {

        if (jweCompact == null || jweCompact.isEmpty()) {
            throw new IllegalArgumentException("El JWE compact no puede ser nulo o vacío");
        }
        LOGGER.debug("JWE recibido: {}", jweCompact);

        JWEObject jweObject = JWEObject.parse(jweCompact);

        String xKeyBase64 = (String) jweObject.getHeader().getCustomParam("x-key");
        String llaveSimetrica = (String) jweObject.getHeader().toJSONObject().get("x-key");
        String base64PrivateKey = rsa.getPrivateKey(TipoCanal.IN.getValue(), institution.getId(), TipoCertificado.PRIVATE.getValue(), institution.getJwe().getKeystore());
        String llaveAES256 = rsa.descifrar(llaveSimetrica, base64PrivateKey);
        SecretKey aesKey = Utilities.fromBase64(llaveAES256, TipoArgorithm.AES.getValue());

        jweObject.decrypt(new DirectDecrypter(aesKey));

        String decryptedPayload = jweObject.getPayload().toString();

        //String response = aes256.descifrar(jweObject.getPayload().toString(), llaveAES256);
        return jweObject.getPayload().toString();
    }

    @Override
    public String sign(String payload, SecurityConfig jwsConfig) throws Exception {
        if (payload == null || payload.trim().isEmpty()) {
            throw new IllegalArgumentException("Payload no puede estar vacío");
        }
        LOGGER.debug("Iniciando firma JWS para payload: {}", payload);

        String base64PrivateKey = rsa.getPrivateKey(TipoCanal.IN.getValue(), null, TipoCertificado.PRIVATE.getValue(), jwsConfig.getKeystore());
        PrivateKey privateKey = toPrivateKey(base64PrivateKey, TipoArgorithm.RSA.getValue());

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
        if (jwsCompact == null || jwsCompact.trim().isEmpty()) {
            throw new IllegalArgumentException("JWS compact no puede estar vacío");
        }
        LOGGER.debug("Iniciando verificación JWS: {}", jwsCompact);

        String base64PrivateKey = rsa.getPublicKey(TipoCanal.IN.getValue(), null, TipoCertificado.PUBLIC.getValue(), jwsConfig.getTruststore());
        PublicKey publicKey = toPublicKey(base64PrivateKey, TipoArgorithm.RSA.getValue());

        JWSObject jwsObject = JWSObject.parse(jwsCompact);

        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
        return jwsObject.verify(verifier);
    }
}
