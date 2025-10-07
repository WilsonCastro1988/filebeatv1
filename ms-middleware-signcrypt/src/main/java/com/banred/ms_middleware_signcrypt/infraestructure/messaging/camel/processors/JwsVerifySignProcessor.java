package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.domain.apim.dto.APIMRequestDTO;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.SecurityConfig;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import com.nimbusds.jose.JWSObject;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;


@Component
public class JwsVerifySignProcessor implements Processor {


    private static final Logger logger = LoggerFactory.getLogger(JwsVerifySignProcessor.class);
    private static final long MAX_AGE_SECONDS = 300; // 5 minutos de validez
    private final CryptoService cryptoService;

    public JwsVerifySignProcessor(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    //@Override
    public void process2(Exchange exchange) throws Exception {
        Institution institution = exchange.getProperty("institution", Institution.class);
        if (institution.getJws() != null && institution.getJws().isEnable()) {

            logger.info("🔏 Aplicando Verify JWS para institución {}", institution.getId());

            String jwsCompact = exchange.getMessage().getBody(String.class);

            boolean isValid = cryptoService.verify(jwsCompact, institution.getJws());
            if (!isValid) {
                logger.error("❌ Firma JWS inválida para institución {}", institution.getId());
                throw new IllegalStateException("❌ Firma JWS inválida");
            }

            logger.info("✅ Firma JWS verificada correctamente");


            JWSObject jwsObject = JWSObject.parse(jwsCompact);
            String payload = jwsObject.getPayload().toString();

            exchange.setProperty("verifiedPayload", payload);
            exchange.getMessage().setBody(payload);
        } else {
            logger.debug("JWS no habilitado para institución {}", institution.getId());
        }
    }


    @Override
    public void process(Exchange exchange) throws Exception {
        Institution institution = exchange.getProperty("institution", Institution.class);

        if (institution.getJws() != null && institution.getJws().isEnable()) {
            logger.info("🔏 Aplicando Verify JWS para institución {}", institution.getId());

            // 1. Obtener headers HTTP
            String signatureInput = (String) exchange.getIn().getHeader("Signature-Input");
            String digestHeader = (String) exchange.getIn().getHeader("digest");
            String signatureHeader = (String) exchange.getIn().getHeader("Signature");
            String jwsCompact = exchange.getMessage().getBody(String.class);

            if (signatureInput == null || digestHeader == null || signatureHeader == null) {
                throw new IllegalStateException("Headers Signature-Input, digest o Signature faltantes");
            }

            // 2. Validar Signature-Input y expiración
            long created = extractCreated(signatureInput);
            long expires = extractExpires(signatureInput);
            long now = Instant.now().getEpochSecond();

            if (now < created || now > expires) {
                //throw new SecurityException("Firma expirada o no válida: created=" + created + ", expires=" + expires + ", now=" + now);
            }
            if (expires - created > MAX_AGE_SECONDS) {
                throw new SecurityException("Validez de firma excede los 5 minutos");
            }
            String expectedKeyId = "'" + institution.getId() + "'";
            if (!signatureInput.contains("keyid=" + expectedKeyId)) {
                throw new SecurityException("keyid no coincide con la institución: " + expectedKeyId);
            }

            // 3. Validar digest
            JWSObject jwsObject = JWSObject.parse(jwsCompact);
            String payload = jwsObject.getPayload().toString();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String calculatedDigest = "SHA-256=" + Base64.getEncoder().encodeToString(digest.digest(payload.getBytes(StandardCharsets.UTF_8)));
            String expectedDigest = digestHeader.replace("SHA-256=:", "").replace(":", "");
            if (!calculatedDigest.equals("SHA-256=" + expectedDigest)) {
                throw new SecurityException("Digest inválido: calculado=" + calculatedDigest + ", esperado=" + digestHeader);
            }

            // 4. Validar firma
            String toVerify = digestHeader + "\n" + signatureInput;
            SecurityConfig jwsConfig = institution.getJws();
            boolean isValidSignature = cryptoService.verify(toVerify, jwsConfig);

            if (!isValidSignature) {
                logger.error("❌ Firma JWS inválida para institución {}", institution.getId());
                throw new IllegalStateException("❌ Firma JWS inválida");
            }

            logger.info("✅ Firma JWS verificada correctamente");
            exchange.setProperty("verifiedPayload", payload);
            exchange.getMessage().setBody(payload);
        } else {
            logger.debug("JWS no habilitado para institución {}", institution.getId());
        }
    }

    private long extractCreated(String signatureInput) {
        String[] parts = signatureInput.split("created=");
        if (parts.length > 1) {
            return Long.parseLong(parts[1].split(";")[0]);
        }
        throw new IllegalArgumentException("created no encontrado en Signature-Input");
    }

    private long extractExpires(String signatureInput) {
        String[] parts = signatureInput.split("expires=");
        if (parts.length > 1) {
            return Long.parseLong(parts[1].split(";")[0]);
        }
        throw new IllegalArgumentException("expires no encontrado en Signature-Input");
    }




}
