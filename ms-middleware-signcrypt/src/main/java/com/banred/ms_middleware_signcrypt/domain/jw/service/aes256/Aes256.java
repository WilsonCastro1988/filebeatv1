package com.banred.ms_middleware_signcrypt.domain.jw.service.aes256;

import com.banred.ms_middleware_signcrypt.common.constant.TipoArgorithm;
import com.banred.ms_middleware_signcrypt.common.exception.AbstractError;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class Aes256 implements IAes256 {

    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12; // 96 bits recomendado para GCM
    private static final int TAG_LENGTH_BIT = 128; // 16 bytes
    private static final int AES_KEY_SIZE = 256;
    

    public Aes256() {
        // Default constructor intentionally left empty as no initialization is required.
    }

    public String cifrar(String plaintext, String base64Key) {
        validarEntradasCifrado(plaintext, base64Key);

        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        validarTamanioLlave(keyBytes);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, TipoArgorithm.AES.getValue());

        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            byte[] iv = generarIv();
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] encrypted = concatenarIvYTextoCifrado(iv, ciphertext);

            return Base64.getEncoder().encodeToString(encrypted);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new AbstractError("3005", "Error al cifrar dato con AES-256-GCM.", "Aes256.cifrar", e);
        }
    }

    public String descifrar(String base64Ciphertext, String base64Key) {
        validarEntradasDescifrado(base64Ciphertext, base64Key);

        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        validarTamanioLlave(keyBytes);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, TipoArgorithm.AES.getValue());

        byte[] encryptedBytes = Base64.getDecoder().decode(base64Ciphertext);
        validarEncryptedBytes(encryptedBytes);

        byte[] iv = extraerIv(encryptedBytes);
        byte[] ciphertext = extraerCiphertext(encryptedBytes);

        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            byte[] decryptedBytes = cipher.doFinal(ciphertext);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new AbstractError("3006", "Error al descifrar dato con AES-256-GCM.", "Aes256.descifrar", e);
        }
    }

    public String generarLlave() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(TipoArgorithm.AES.getValue());
            keyGen.init(AES_KEY_SIZE, new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new AbstractError(e, "Aes256.generarLlave");
        }
    }


    private void validarEntradasCifrado(String plaintext, String base64Key) {
        if (plaintext == null || base64Key == null) {
            throw new AbstractError("3001", "El texto plano y la llave no deben ser null.", "Aes256.validarEntradasCifrado");
        }
    }

    private void validarEntradasDescifrado(String base64Ciphertext, String base64Key) throws AbstractError {
        if (base64Ciphertext == null || base64Key == null) {
            throw new AbstractError("3002", "El texto cifrado y la llave no deben ser null.", "Aes256.validarEntradasDescifrado");
        }
    }

    private void validarTamanioLlave(byte[] keyBytes) throws AbstractError {
        if (keyBytes.length != 32) {
            throw new AbstractError("3003", "La longitud de la llave debe ser de 256 bits (32 bytes).", "Aes256.validarTamanioLlave");
        }
    }

    private void validarEncryptedBytes(byte[] encryptedBytes) {
        if (encryptedBytes.length < IV_LENGTH + (TAG_LENGTH_BIT / 8)) {
            throw new AbstractError("3004", "El texto cifrado no es válido.", "Aes256.validarEncryptedBytes");
        }
    }

    private byte[] generarIv() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private byte[] concatenarIvYTextoCifrado(byte[] iv, byte[] ciphertext) {
        byte[] encrypted = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(ciphertext, 0, encrypted, iv.length, ciphertext.length);
        return encrypted;
    }

    private byte[] extraerIv(byte[] encryptedBytes) {
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(encryptedBytes, 0, iv, 0, IV_LENGTH);
        return iv;
    }

    private byte[] extraerCiphertext(byte[] encryptedBytes) {
        int ciphertextLength = encryptedBytes.length - IV_LENGTH;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(encryptedBytes, IV_LENGTH, ciphertext, 0, ciphertextLength);
        return ciphertext;
    }
}
