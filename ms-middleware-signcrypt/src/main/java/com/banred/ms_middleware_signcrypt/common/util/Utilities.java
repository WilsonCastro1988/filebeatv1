package com.banred.ms_middleware_signcrypt.common.util;

import com.banred.ms_middleware_signcrypt.domain.apim.dto.APIMRequestDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;

public class Utilities {

    // Private constructor to prevent instantiation
    private Utilities() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    private static final Logger logger = LoggerFactory.getLogger(Utilities.class);


    public static SecretKey fromBase64(String base64Key, String algorithm) {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, algorithm);
    }


    public static PrivateKey toPrivateKey(String base64Key, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePrivate(keySpec);
    }


    public static PublicKey toPublicKey(String base64PublicKey, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(keySpec);
    }


    public static String readKeyAsBase64(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String getDateStringISO8601(Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        return sdf.format(date);
    }


    public static APIMRequestDTO jsonToDtoConverter(String jsonObject) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.readValue(jsonObject, APIMRequestDTO.class);
        } catch (Exception e) {
            logger.error("ERROR from InstitutionLookUpProcessor", e);
            return null;
        }
    }

    public static Map<String, Object> obtenerHeaders(HttpHeaders headers) {
        Map<String, Object> headerMap = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            headerMap.put(entry.getKey(), entry.getValue().get(0));
        }

        return headerMap;
    }

}
