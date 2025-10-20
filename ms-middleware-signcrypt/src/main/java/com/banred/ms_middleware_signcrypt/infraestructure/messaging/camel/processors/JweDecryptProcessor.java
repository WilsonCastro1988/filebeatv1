package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.domain.apim.dto.APIMRequestDTO;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class JweDecryptProcessor implements Processor {

    private static final Logger logger = LoggerFactory.getLogger(JweDecryptProcessor.class);

    private final CryptoService cryptoService;

    public JweDecryptProcessor(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @Override
    public void process(Exchange exchange) throws Exception {
        Institution institution = exchange.getProperty("institution", Institution.class);

        if (institution.getJwe() != null && institution.getJwe().isEnable()) {

            logger.info("🔐 Aplicando Decrypt JWE para institución {}", institution.getId());

            String encryptedMessage = exchange.getMessage().getBody(String.class);

            if (encryptedMessage == null || encryptedMessage.trim().isEmpty()) {
                throw new IllegalArgumentException("Mensaje cifrado no puede estar vacío");
            }

            APIMRequestDTO obj = jsonToDtoConverter(encryptedMessage);
            if (obj == null) {
                throw new IllegalArgumentException("El objeto APIMRequestDTO no puede ser nulo");
            }
            String jwsCompact = cryptoService.decrypt(obj.getData(), institution);
            logger.info("📤 Datos descifrados: {}", jwsCompact);

            exchange.setProperty("jwsCompact", jwsCompact);
            exchange.getMessage().setBody(jwsCompact);
        } else {
            logger.debug("JWE no habilitado para institución {}", institution.getId());
        }
    }

    public static APIMRequestDTO jsonToDtoConverter(String jsonObject) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.readValue(jsonObject, APIMRequestDTO.class);
        } catch (JsonProcessingException e) {
            return null;
        }
    }
}
