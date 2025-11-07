package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.domain.apim.dto.APIMRequestDTO;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import static com.banred.ms_middleware_signcrypt.common.util.Utilities.jsonToDtoConverter;

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

            exchange.setProperty("payloadDto", obj);
            exchange.setProperty("jwsCompact", jwsCompact);
            exchange.getMessage().setBody(jwsCompact);
        } else {
            logger.debug("JWE no habilitado para institución {}", institution.getId());
        }
    }
}
