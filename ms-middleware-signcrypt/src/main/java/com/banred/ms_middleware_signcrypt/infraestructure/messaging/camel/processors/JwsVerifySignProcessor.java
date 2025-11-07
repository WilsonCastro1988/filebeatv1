package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.domain.apim.dto.APIMRequestDTO;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import static com.banred.ms_middleware_signcrypt.common.util.Utilities.extractPayload;

@Component
public class JwsVerifySignProcessor implements Processor {

    private static final Logger logger = LoggerFactory.getLogger(JwsVerifySignProcessor.class);
    private final CryptoService cryptoService;

    public JwsVerifySignProcessor(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @Override
    public void process(Exchange exchange) throws Exception {
        Institution institution = exchange.getProperty("institution", Institution.class);
        APIMRequestDTO apimRequestDTO = exchange.getProperty("payload", APIMRequestDTO.class);

        if (institution == null || institution.getJws() == null || !institution.getJws().isEnable()) {
            logger.debug("⚠️ JWS no habilitado para esta institución o configuración inválida.");
            return;
        }

        logger.info("🔎 Verificando JWS para institución {}", institution.getId());

        try {
            // Extraer headers y cuerpo del mensaje
            String jwsCompact = exchange.getMessage().getBody(String.class);
            String digestHeader = apimRequestDTO.getSign().getDigest();
            String signatureInput = apimRequestDTO.getSign().getSignatureInput();
            String signatureHeader = apimRequestDTO.getSign().getSignature();

            // Validación de presencia
            if (digestHeader == null || signatureInput == null || signatureHeader == null) {
                throw new IllegalStateException("Faltan headers: digest, Signature-Input o Signature");
            }

            // Verificar todoel contenido criptográfico
            cryptoService.verifyWithHeaders(jwsCompact, digestHeader, signatureInput, institution);

            // Extraer contenido firmado si se requiere
            String signedContent = extractPayload(jwsCompact);
            exchange.setProperty("verifiedPayload", signedContent);

            exchange.getMessage().setBody(signedContent);

            logger.info("✅ Firma JWS verificada correctamente para institución {}", institution.getId());

        } catch (Exception e) {
            logger.error("❌ Error al verificar firma JWS: {}", e.getMessage(), e);
            exchange.setException(e);
        }
    }
}
