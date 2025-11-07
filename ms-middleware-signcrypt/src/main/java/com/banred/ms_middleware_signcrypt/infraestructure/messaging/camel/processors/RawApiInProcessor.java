package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractError;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import static com.banred.ms_middleware_signcrypt.common.util.Utilities.extractPayload;

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

        logger.info("🔓 Procesando respuesta raw-api para institución {}", institution.getId());

        // Extraer 'data' del JSON
        JsonNode jsonNode = objectMapper.readTree(payload);
        if (!jsonNode.has("data")) {
            throw new AbstractError("500", "Payload no contiene el campo 'data'", "T");
        }
        String jwePayload = jsonNode.get("data").asText();
        String decrypted = cryptoService.decrypt(jwePayload, institution);

        // Verificar JWS usando headers
        cryptoService.verifyWithHeaders(
                decrypted,
                exchange.getIn().getHeader("digest", String.class),
                exchange.getIn().getHeader("Signature-Input", String.class),
                institution
        );
        String signedContent = extractPayload(decrypted);
        exchange.getMessage().setBody(signedContent);
        logger.info("✅ Respuesta raw-api procesada correctamente para institución {}", institution.getId());
    }
}
