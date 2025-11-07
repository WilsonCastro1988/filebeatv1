package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractError;
import com.banred.ms_middleware_signcrypt.common.exception.AbstractException;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.springframework.stereotype.Component;

@Component
public class MiddlerwareLookupProcessor implements Processor {


    private final IInstitutionRedisService institutionRedisService;

    public MiddlerwareLookupProcessor(IInstitutionRedisService institutionRedisService) {
        this.institutionRedisService = institutionRedisService;
    }

    @Override
    public void process(Exchange exchange)  {
        try {
            String xEntityID = exchange.getIn().getHeader("X-Entity-ID", String.class);
            String signature = exchange.getIn().getHeader("Signature", String.class);
            String signatureInput = exchange.getIn().getHeader("Signature-Input", String.class);
            String digest = exchange.getIn().getHeader("digest", String.class);
            String xKey = exchange.getIn().getHeader("x-key", String.class);

            Institution institution = null;

            if (xEntityID.isEmpty()) {
                throw new AbstractError("400", "Header X-Entity-ID no presente", "T");
            } else {
                institution = institutionRedisService.getInstitution(xEntityID);
                if (institution == null) {
                    throw new AbstractError("400", "Institucion no encontrada", "T");
                }
                exchange.setProperty("institution", institution);
            }

            if (signature == null || signature.isEmpty() || signatureInput == null || signatureInput.isEmpty()
                    || digest == null || digest.isEmpty() || xKey == null || xKey.isEmpty()) {
                exchange.setProperty("middleware", "out");
            } else {
                exchange.setProperty("middleware", "in");
                exchange.setProperty("signature", signature);
                exchange.setProperty("signatureInput", signatureInput);
                exchange.setProperty("digest", digest);
                exchange.setProperty("xKey", xKey);
            }
        } catch (AbstractException e) {
            exchange.setProperty(Exchange.EXCEPTION_CAUGHT, e);
            throw e;
        } catch (JsonProcessingException e) {
            throw new AbstractError(e, "T");
        }
    }
}
