package com.banred.ms_middleware_signcrypt.components;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.Security;
import java.util.List;

@Component
public class CrlUpdater {

    private static final Logger logger = LoggerFactory.getLogger(CrlUpdater.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Value("${microservice.parameters.RUTA_CRL}")
    private String rutaLocalCrl;

    // Lista de URLs de CRLs de diferentes CAs
    private final List<String> crlUrls = List.of(
            "http://crl3.digicert.com/DigiCertGlobalRootG3.crl"
            // Agregar más URLs de CAs aquí
    );

    private final Path crlDir = Path.of("D:\\OneDrive - BANRED S.A\\Documentos\\Microservicios\\filebeatv1\\ms-middleware-signcrypt\\src\\main\\resources\\certs\\ca\\crl"); // carpeta local donde guardas las CRL

    private byte[] lastCRLHash = null;

    @Scheduled(cron = "0 0 2 * * ?", zone = "America/Guayaquil")
    public void actualizarCRLs() {
        try {
            Security.addProvider(new BouncyCastleProvider());
            Files.createDirectories(crlDir);

            for (String urlStr : crlUrls) {
                URL url = new URL(urlStr);
                try (InputStream in = url.openStream()) {
                    byte[] crlBytes = in.readAllBytes();
                    byte[] hash = MessageDigest.getInstance("SHA-256").digest(crlBytes);

                    // Solo actualizar si hay cambios
                    if (lastCRLHash == null || !MessageDigest.isEqual(lastCRLHash, hash)) {
                        String crlFileName = "crl.der";
                        Path crlPath = crlDir.resolve(crlFileName);
                        try (FileOutputStream fos = new FileOutputStream(crlPath.toFile())) {
                            fos.write(crlBytes);
                        }
                        lastCRLHash = hash;
                        System.out.println("CRL actualizada desde: " + urlStr);
                    } else {
                        System.out.println("CRL sin cambios, no se actualiza: " + urlStr);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
