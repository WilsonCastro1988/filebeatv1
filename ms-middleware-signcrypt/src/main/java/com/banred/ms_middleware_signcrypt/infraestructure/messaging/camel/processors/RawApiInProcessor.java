package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class RawApiInProcessor implements Processor {

    private static final Logger logger = LoggerFactory.getLogger(RawApiInProcessor.class);
    private final CryptoService cryptoService;
    private final ObjectMapper objectMapper;

    public RawApiInProcessor(CryptoService cryptoService, ObjectMapper objectMapper) {
        this.cryptoService = cryptoService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void process(Exchange exchange) throws Exception {
        Institution institution = exchange.getProperty("institution", Institution.class);
        String payload = exchange.getMessage().getBody(String.class);

        if (institution == null) {
            throw new IllegalStateException("⚠️ Institución no encontrada en exchange");
        }

        logger.info("🔓 Procesando respuesta raw-api para institución {}", institution.getId());

        // 1️⃣ Extraer 'data' del JSON
        JsonNode jsonNode = objectMapper.readTree(payload);
        if (!jsonNode.has("data")) {
            throw new IllegalArgumentException("Payload no contiene el campo 'data'");
        }

        String jwePayload = jsonNode.get("data").asText();

        // 2️⃣ Desencriptar JWE
        String decrypted = cryptoService.decrypt(jwePayload, institution);

        // 3️⃣ Verificar JWS usando headers
        cryptoService.verifyWithHeaders(
                decrypted,
                exchange.getIn().getHeader("digest", String.class),
                exchange.getIn().getHeader("Signature-Input", String.class),
                institution
        );

        // 4️⃣ Dejar payload limpio en el body (puedes devolver solo el contenido o re-encapsularlo)
        exchange.getMessage().setBody(decrypted);
        logger.info("✅ Respuesta raw-api procesada correctamente para institución {}", institution.getId());
    }
}
