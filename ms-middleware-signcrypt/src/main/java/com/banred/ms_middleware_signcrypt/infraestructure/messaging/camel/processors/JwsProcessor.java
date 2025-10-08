package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.jw.dto.JWSResponse;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class JwsProcessor implements Processor {

    private static final Logger logger = LoggerFactory.getLogger(JwsProcessor.class);
    private final CryptoService cryptoService;

    public JwsProcessor(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @Override
    public void process(Exchange exchange) throws Exception {
        Institution institution = exchange.getProperty("institution", Institution.class);

        if (institution == null || institution.getJws() == null || !institution.getJws().isEnable()) {
            logger.debug("⚠️ JWS no habilitado para esta institución o configuración inválida.");
            return;
        }

        String payload = exchange.getMessage().getBody(String.class);
        logger.info("🔏 Aplicando JWS para institución {}", institution.getId());

        try {
            // 🔹 Firma y genera todos los encabezados en un solo paso
            JWSResponse jwsResponse = cryptoService.signWithHeaders(payload, institution);

            // 🔹 Asignar headers al Exchange
            exchange.getIn().setHeader("digest", jwsResponse.getDigestHeader());
            exchange.getIn().setHeader("Signature-Input", jwsResponse.getSignatureInput());
            exchange.getIn().setHeader("Signature", jwsResponse.getSignatureHeader());
            exchange.getIn().setHeader("X-Entity-ID", institution.getId());

            // 🔹 Colocar el cuerpo firmado
            exchange.getMessage().setBody(jwsResponse.getJwsCompact());
            exchange.setProperty("jwsResponse", jwsResponse.getJwsCompact());

            logger.info("📤 JWS generado y aplicado exitosamente.");
        } catch (Exception e) {
            logger.error("❌ Error al aplicar JWS: {}", e.getMessage(), e);
            exchange.setException(e);
        }
    }
}
