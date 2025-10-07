package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
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
public class JwsProcessor implements Processor {

    private static final Logger logger = LoggerFactory.getLogger(JwsProcessor.class);
    private static final long EXPIRY_SECONDS = 300; // 5 minutos de validez

    private final CryptoService cryptoService;

    public JwsProcessor(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    //@Override
    public void process2(Exchange exchange) throws Exception {
        Institution institution = exchange.getProperty("institution", Institution.class);

        if (institution.getJws() != null && institution.getJws().isEnable()) {
            logger.info("🔏 Aplicando JWS para institución {}", institution.getId());

            String body = exchange.getMessage().getBody(String.class);

            // Firmar el contenido
            String signedData = cryptoService.sign(body, institution.getJws());
            logger.info("📤 Datos firmados (JWS): {}", signedData);

            exchange.setProperty("jwsResponse", signedData);
            exchange.getMessage().setBody(signedData);
        } else {
            logger.debug("JWS no habilitado para institución {}", institution.getId());
        }
    }

    @Override
    public void process(Exchange exchange) throws Exception {
        Institution institution = exchange.getProperty("institution", Institution.class);

        if (institution.getJws() != null && institution.getJws().isEnable()) {
            logger.info("🔏 Aplicando JWS para institución {}", institution.getId());

            String payload = exchange.getProperty("payload", String.class);

            // 1. Calcular digest
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String digestBase64 = Base64.getEncoder().encodeToString(digest.digest(payload.getBytes(StandardCharsets.UTF_8)));
            String digestHeader = "SHA-256=" + digestBase64;

            // 2. Construir Signature-Input
            long created = Instant.now().getEpochSecond();
            long expires = created + EXPIRY_SECONDS;
            String signatureInput = "sig1=(\"digest\");created=" + created + ";keyid=\"" + institution.getId() + "\";alg=\"rsa-sha256\";expires=" + expires;

            // 3. Construir cadena a firmar y firmar con JWS
            String toSign = digestHeader + "\n" + signatureInput;
            String jwsCompact = cryptoService.sign(toSign, institution.getJws());

            // 4. Extraer y formatear la firma
            JWSObject jwsObject = JWSObject.parse(jwsCompact);
            String signature = Base64.getEncoder().encodeToString(jwsObject.getSignature().decode());
            String signatureHeader = "sig1=" + signature;

            // 5. Guardar en headers del Exchange
            exchange.getIn().setHeader("Signature-Input", signatureInput);
            exchange.getIn().setHeader("digest", digestHeader);
            exchange.getIn().setHeader("Signature", signatureHeader);
            exchange.getIn().setHeader("X-Entity-ID", institution.getId());

            // 6. Actualizar body con el JWS completo
            exchange.getMessage().setBody(jwsCompact);
            exchange.setProperty("jwsResponse", jwsCompact);

            logger.info("📤 Datos firmados (JWS): {}", jwsCompact);
        } else {
            logger.debug("JWS no habilitado para institución {}", institution.getId());
        }
    }
}
