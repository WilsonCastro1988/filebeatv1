package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import com.nimbusds.jose.JWEObject;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class JweProcessor implements Processor {


    private static final Logger logger = LoggerFactory.getLogger(JweProcessor.class);

    private final CryptoService cryptoService;

    public JweProcessor(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @Override
    public void process(Exchange exchange) throws Exception {
        try {
            Institution institution = exchange.getProperty("institution", Institution.class);

            if (institution.getJwe() != null && institution.getJwe().isEnable()) {
                logger.info("🔐 Aplicando JWE para institución {}", institution.getId());

                String payload = exchange.getMessage().getBody(String.class);

                // Cifrar el contenido
                String encryptedData = cryptoService.encrypt(payload, institution);
                JWEObject jweObject = JWEObject.parse(encryptedData);
                String jweCompact = jweObject.serialize();
                String xKey = (String) jweObject.getHeader().getCustomParam("x-key"); // Asume que CryptoService lo incluye

                if (xKey == null) {
                    throw new IllegalStateException("x-key no generado durante la encriptación");
                }

                exchange.getIn().setHeader("x-key", xKey);
                logger.info("📤 Datos cifrados (JWE): {}", jweCompact);

                exchange.setProperty("jweResponse", jweCompact);
                exchange.getMessage().setBody(jweCompact);
            } else {
                logger.debug("JWE no habilitado para institución {}", institution.getId());
            }
        } catch (Exception e) {
            exchange.setException(e);
        }
    }

}
