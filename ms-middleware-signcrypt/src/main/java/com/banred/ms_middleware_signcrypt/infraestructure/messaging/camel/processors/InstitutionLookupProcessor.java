package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.springframework.stereotype.Component;

@Component
public class InstitutionLookupProcessor implements Processor {

    private final IInstitutionRedisService institutionRedisService;

    public InstitutionLookupProcessor(IInstitutionRedisService institutionRedisService) {
        this.institutionRedisService = institutionRedisService;
    }

    @Override
    public void process(Exchange exchange) throws JsonProcessingException {
        try {
            String institutionId = exchange.getIn().getBody(String.class);

            Institution institution = institutionRedisService.getInstitution(institutionId);

            if (institution == null || institution.getEndpoint() == null) {
                throw new RuntimeException("Institución no encontrada o endpoint no definido");
            }

            exchange.getIn().setHeader("ifiEndpoint", institution.getEndpoint());
            exchange.getIn().setHeader("mtlsEnabled", institution.getMtls() != null && institution.getMtls().isEnable());
            exchange.getIn().setHeader("jwsEnabled", institution.getJws() != null && institution.getJws().isEnable());
            exchange.getIn().setHeader("jweEnabled", institution.getJwe() != null && institution.getJwe().isEnable());

            // Pasar institución completa al Exchange si se necesita después
            exchange.setProperty("institution", institution);
        }catch (Exception e) {
            exchange.setException(e);
        }

    }
}
