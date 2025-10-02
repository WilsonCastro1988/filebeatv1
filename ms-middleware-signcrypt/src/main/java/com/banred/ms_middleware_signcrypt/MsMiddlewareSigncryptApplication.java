package com.banred.ms_middleware_signcrypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.io.ClassPathResource;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.*;
import java.util.List;

@SpringBootApplication
public class MsMiddlewareSigncryptApplication {

    @Value("${microservice.parameters.RUTA_CRL}")
    private String rutaCRL;

    public static void main(String[] args) throws CertificateException, NoSuchProviderException, FileNotFoundException {
        SpringApplication.run(MsMiddlewareSigncryptApplication.class, args); // 1. Load the certificates (replace with your actual certificate loading)

        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");

        try (InputStream in = new ClassPathResource("certs/ca/crl/crl.der").getInputStream()) {
            X509CRL crl = (X509CRL) certificateFactory.generateCRL(in);

            System.out.println("CRL emitido por: " + crl.getIssuerX500Principal());
            System.out.println("Próxima actualización: " + crl.getNextUpdate());

            if (crl.getRevokedCertificates() != null) {
                crl.getRevokedCertificates().forEach(revoked ->
                        System.out.println("Revocado: " + revoked.getSerialNumber()));
            } else {
                System.out.println("No hay certificados revocados en esta CRL");
            }

        } catch (IOException | CRLException e) {
            throw new RuntimeException(e);
        }

    }

    public static boolean validateCertificateChain(final List<X509Certificate> certificates) {
        for (int i = 0; i < certificates.size(); i++) {
            try {
                if (i == certificates.size() - 1) {
                    if (isSelfSigned(certificates.get(i))) {
                        certificates.get(i).verify(certificates.get(i).getPublicKey());
                    }
                } else {
                    certificates.get(i).verify(certificates.get(i + 1).getPublicKey());
                }
            } catch (Exception e) {
                return false;
            }
        }
        return true;
    }

    /**
     * Determine if the given certificate is self signed.
     *
     * @param certificate Certificate to be verified as self-signed against its own public key.
     * @return <code>true if the certificate is self signed
     * <code>false</code> otherwise, in the case of any exception.
     */
    private static boolean isSelfSigned(final X509Certificate certificate) {
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

}
