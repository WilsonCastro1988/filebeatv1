package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractError;
import com.banred.ms_middleware_signcrypt.domain.apim.dto.APIMRequestDTO;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
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
    public void process(Exchange exchange) {
        try {
            APIMRequestDTO apimRequestDTO = jsonToDtoConverter(exchange.getIn().getBody(String.class));
            Institution institution = institutionRedisService.getInstitution(apimRequestDTO.getXEntityID());

            if (institution == null || institution.getEndpoint() == null) {
                throw new AbstractError("400", "Institución no encontrada o endpoint no definido", "T");
            }

            exchange.getIn().setHeader("ifiEndpoint", institution.getEndpoint());
            exchange.getIn().setHeader("timestamp_in", getDateStringISO8601(new Date()));

            // Pasar institución completa al Exchange si se necesita después
            exchange.setProperty("institution", institution);
            exchange.setProperty("payload", apimRequestDTO);
        } catch (Exception e) {
            exchange.setException(e);
        }
    }
}
