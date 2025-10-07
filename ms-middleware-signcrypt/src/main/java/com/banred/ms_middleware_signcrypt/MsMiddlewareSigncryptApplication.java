package com.banred.ms_middleware_signcrypt;

import com.banred.ms_middleware_signcrypt.domain.jw.service.aes256.Aes256;
import com.banred.ms_middleware_signcrypt.domain.jw.service.rsa.Rsa;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

@SpringBootApplication
@EnableScheduling
public class MsMiddlewareSigncryptApplication {

    public static void main(String[] args) {
        SpringApplication.run(MsMiddlewareSigncryptApplication.class, args);

        String llaveTest = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArFshW/Yij6JTJCgrUzExPcrLYKrdkonWA2WmKL9EV3WvXYIlR1xTk+CnlleKp6S7z5rsUxWe+2rMN1tssdV0rAwHgzqyM2jg8ts5OIwKS3HawYYPQlPXhimpwwn3YjiHj8REdoLF+p/vIjl/Xx19pXlwoc6EEp6d1xgWC/lBxkbnK/4xwzVbeikDYyG/ObEMnfs62eTZZG0sZa9hCsv6SeUtUz45UmRKUtM6IAio2KjcvmvKzL/m4oCV5POKuTWQBrMYWCbuOiPXgzNz027nxQtqjQs9i6eCS5dg6zscruhrsO2mZwaarOxkinEzvoFP50nlfvoflWLKE4R6BuXiywIDAQAB";
        String llavePrivadaTest = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsWyFb9iKPolMkKCtTMTE9ystgqt2SidYDZaYov0RXda9dgiVHXFOT4KeWV4qnpLvPmuxTFZ77asw3W2yx1XSsDAeDOrIzaODy2zk4jApLcdrBhg9CU9eGKanDCfdiOIePxER2gsX6n+8iOX9fHX2leXChzoQSnp3XGBYL+UHGRucr/jHDNVt6KQNjIb85sQyd+zrZ5NlkbSxlr2EKy/pJ5S1TPjlSZEpS0zogCKjYqNy+a8rMv+bigJXk84q5NZAGsxhYJu46I9eDM3PTbufFC2qNCz2Lp4JLl2DrOxyu6Guw7aZnBpqs7GSKcTO+gU/nSeV++h+VYsoThHoG5eLLAgMBAAECggEAH+9WtAJcDv8FpqpmtKhltkxP+J5QJamyZLi928jsscPVdV7650j9F2ZFxv57a2qDfgj3hsF3zp/QLOWcsyqYzpQABFmo0Qu6umTSKl8QPUBgRwE+7Iw6X9pyYPgExUcyHvo/sTGz2yctGMtMhWQidrmUm/Z21DhdiJAm7ZsGi+UjVz40pt0gqmOfea6XFx/pxJdLCNq2POjLZowbpr2gCYVM3wZ3aXkjWpY6FvH5Xvv5ul1/FkTzQ3Fy1YzI873t1wI2put8foXrCnwC0rTDCIZTJlD5gL9BUvtXSCKuwrbPuQ9+AhaWOS4YVuP1DNyrBlELxmw3u0yD0PB1OvLMwQKBgQDdZ5yQV5hE0PEKPHlqxuy/P1FceF9cBKVqMkOgKsB/5X4HbaftS44Tk2oGDDFCpS9prTZdLOXO6M9obNfff5S/9Hz4FM8RVvfDDoXntrLCL2sJWolYRfom5LqQ/J3nbWHu5agqhzr5e/fhBv3SML6KTVYtoNZI9iO7rvaHJ6teawKBgQDHSYZAnCDRxl5+PGRNf0oc1AFYogm8YB3vipBI1jxfRwytLIALz9fR2sNmRTbfl7vNCdioTQUBbifdMESvHTurbodiNH+dbhg1a3FfXGP8qHdhwMRO23MVqD7GdMgHKYAyH7jHzLmDeGqwZcgsrwNkE2z1oOAj9h7XIIRKH0vlIQKBgGn22uHiaogVECf8BYhrKIfnwALnwYwC1UBcSi1wCK2tooHfo41YqekIlqfKUhE5idWkBu7VPC+pEQtDfJYFM6YjV2RMYUZFP1NlsgTSVf/GPg49/Jn4896Ffh1CKjjHCyYRWEjya/FXua1DcVuV5LvAg8xWu/gzhaqf9HF/NO99AoGABur7eRSyYvXS4+juxm3rwbJuVYhSdDKV93HE7nJZaClMPFq2GzLc2BETBWLTs9FNmKGF3tnFmbYcNiZty/Jk1t+gXX1bDLj8qCYRqnDHm8axVjhd2CrwBMlxXGxDYVREefj17iGiMvkkIvl1iG+O25N9Dc3G2hi6G1eqn/QUK2ECgYEAyeVkhHQderQ7tmS4F0qkTEa/iHSVX5kIJvVvcWjlUtMz6wbvhgu/Kh0Jy0O6I3wGFt/z5QPoTl2fG6rxoGRL1D5vWMPYKohAbt8/XmYTIqjy/2q83xlMcWmIzut2YVV/eJjg5qjWnWy5dXgju8EsO75rPQRyXh86KswIR/lU5kY=";

        Rsa rsa = new Rsa();
        Aes256 aes256Gcm = new Aes256();

        String llavePublica = llaveTest;
        String llaveSimetrica = aes256Gcm.generarLlave();
        String textoPlano = "4334260024593955";

        String datoCifrado = aes256Gcm.cifrar(textoPlano, llaveSimetrica);
        String llaveSimetricaCifrada = rsa.cifrar(llaveSimetrica, llavePublica);

        System.out.println("<==========================================>");
        System.out.println("PROCESO CIFRADO AES+RSA: ");
        System.out.println("<==========================================>");
        System.out.println("Tarjeta cifrada (Base64): " + datoCifrado);
        System.out.println("Llave AES Generada (Base64): " + llaveSimetrica);
        System.out.println("Llave AES Encriptada (RSA): " + llaveSimetricaCifrada);


        System.out.println("<==========================================>");
        System.out.println("PROCESO DECIFRADO AES+RSA: ");
        System.out.println("<==========================================>");
        System.out.println("Llave AES Decifrada (RSA): " + rsa.descifrar(llaveSimetricaCifrada, llavePrivadaTest));
        System.out.println("Dato Decifrado (Base64): " + aes256Gcm.descifrar(datoCifrado, llaveSimetrica));

        System.out.println("<==========================================>");
    }
}
