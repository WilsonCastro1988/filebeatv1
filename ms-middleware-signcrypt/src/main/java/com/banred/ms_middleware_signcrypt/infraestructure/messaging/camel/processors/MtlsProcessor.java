package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;


import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.mtls.service.RestTemplateService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class MtlsProcessor implements Processor {

    private final RestTemplateService restTemplateService;

    public MtlsProcessor(RestTemplateService restTemplateService) {
        this.restTemplateService = restTemplateService;
    }

    @Override
    public void process(Exchange exchange) {
        try {
            Institution institution = exchange.getProperty("institution", Institution.class);
            String endpoint = exchange.getIn().getHeader("ifiEndpoint", String.class);

            RestTemplate restTemplate = restTemplateService.getRestTemplate(institution);
            ResponseEntity<String> response = restTemplate.getForEntity(endpoint, String.class);

            exchange.getIn().setBody(response.getBody());
        }catch (Exception e){
            exchange.setException(e);
        }


    }
}
