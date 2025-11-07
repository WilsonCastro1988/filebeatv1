package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractError;
import com.banred.ms_middleware_signcrypt.common.exception.AbstractException;
import com.banred.ms_middleware_signcrypt.domain.apim.dto.APIMRequestDTO;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.springframework.stereotype.Component;
import java.util.Date;
import static com.banred.ms_middleware_signcrypt.common.util.Utilities.getDateStringISO8601;
import static com.banred.ms_middleware_signcrypt.common.util.Utilities.jsonToDtoConverter;

@Component
public class InstitutionLookupProcessor implements Processor {


    private final IInstitutionRedisService institutionRedisService;

    public InstitutionLookupProcessor(IInstitutionRedisService institutionRedisService) {
        this.institutionRedisService = institutionRedisService;
    }

    @Override
    public void process(Exchange exchange) throws AbstractException {
        try {
            APIMRequestDTO apimRequestDTO = jsonToDtoConverter(exchange.getIn().getBody(String.class));
            Institution institution = institutionRedisService.getInstitution(apimRequestDTO.getXEntityID());

            if (institution == null) {
                throw new AbstractError("400","Institución no encontrada", "T");
            }

            exchange.getIn().setHeader("timestamp_in", getDateStringISO8601(new Date()));

            exchange.setProperty("institution", institution);
            exchange.setProperty("payload", apimRequestDTO);
        } catch (AbstractException e) {
            exchange.setProperty(Exchange.EXCEPTION_CAUGHT, e);
            throw e;
        } catch (JsonProcessingException e) {
            throw new AbstractError(e, "T");
        }
    }
}
