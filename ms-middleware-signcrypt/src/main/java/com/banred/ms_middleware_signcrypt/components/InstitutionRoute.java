package com.banred.ms_middleware_signcrypt.components;

import com.banred.ms_middleware_signcrypt.model.Institution;
import com.banred.ms_middleware_signcrypt.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.service.RestTemplateService;
import com.banred.ms_middleware_signcrypt.service.CryptoService;
import com.banred.ms_middleware_signcrypt.service.RestTemplateService2;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class InstitutionRoute extends RouteBuilder {
    @Autowired
    private IInstitutionRedisService institutionRedisService;


    @Autowired
    private RestTemplateService2 restTemplateService;

    @Autowired
    private CryptoService cryptoService;

/*
    @Override
    public void configure() throws Exception {
       from("direct:getInstitution")
            .process(exchange -> {
                String id = exchange.getIn().getBody(String.class);
                Institution institution = institutionRedisService.getInstitution(id);
                if (institution == null || institution.getEndpoint() == null) {
                    throw new RuntimeException("No se encontró endpoint para IFI " + id);
                }
                exchange.getIn().setHeader("ifiEndpoint",institution.getEndpoint());
                // TO DO logica para implementar mecanismos de seguridad
                exchange.getIn().setBody("OK");
            })
            .toD("{header.ifiEndpoint}");

    }*/


    @Override
    public void configure() {
        from("direct:secureInstitutionCall")
                .routeId("secureInstitutionCallRoute")
                .log("Recibiendo solicitud para institución: ${body}")
                .process(exchange -> {
                    String institutionId = exchange.getIn().getBody(String.class);

                    // Obtener institución desde Redis
                    Institution institution = institutionRedisService.getInstitution(institutionId);

                    if (institution == null || institution.getEndpoint() == null) {
                        throw new RuntimeException("Institución no encontrada o endpoint no definido");
                    }

                    exchange.getIn().setHeader("ifiEndpoint", institution.getEndpoint());

                    RestTemplate restTemplate = null;
                    ResponseEntity<String> response = null;
                    String responseBody = null;

                    //Apicar MTLS
                    if (institution.getMtls() != null && institution.getMtls().isEnable()) {
                        restTemplate = restTemplateService.getRestTemplate(institution.getId());
                        response = restTemplate.getForEntity(institution.getEndpoint(), String.class);
                    }

                    // Aplicar JWS
                    if (institution.getJws() != null && institution.getJws().isEnable()) {
                        responseBody = cryptoService.encryptData(institutionId);
                        responseBody = cryptoService.decrypt(responseBody, institution.getJwe());
                    }
/*
                    // Aplicar JWE
                    if (institution.getJwe() != null && institution.getJwe().isEnable()) {
                        responseBody = securityProcessor.encrypt(responseBody, institution.getJwe());
                    }*/


                    log.info(response.getBody());
                    log.info(responseBody);

                    exchange.getMessage().setBody(responseBody);
                });
    }

}
