package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.route;

import com.banred.ms_middleware_signcrypt.domain.mtls.service.WebClientService;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.InstitutionLookupProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.JweProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.JwsProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.MtlsProcessor;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import com.banred.ms_middleware_signcrypt.domain.mtls.service.RestTemplateService;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

@Component
public class InstitutionRoute extends RouteBuilder {


    /*
    private final InstitutionLookupProcessor institutionLookupProcessor;
    private final MtlsProcessor mtlsProcessor;
    private final JwsProcessor jwsProcessor;
    private final JweProcessor jweProcessor;

    public InstitutionRoute(InstitutionLookupProcessor institutionLookupProcessor,
                            MtlsProcessor mtlsProcessor,
                            JwsProcessor jwsProcessor,
                            JweProcessor jweProcessor) {
        this.institutionLookupProcessor = institutionLookupProcessor;
        this.mtlsProcessor = mtlsProcessor;
        this.jwsProcessor = jwsProcessor;
        this.jweProcessor = jweProcessor;
    }

    @Override
    public void configure() {

        onException(Exception.class)
                .log(LoggingLevel.ERROR, "❌ Error en secureInstitutionCall: ${exception.message}")
                .handled(true)
                .setBody(constant("Error interno en la ruta"));

        from("direct:secureInstitutionCall")
                .routeId("secureInstitutionCallRoute")
                .log("📩 Recibiendo solicitud para institución: ${body}")
                .process(institutionLookupProcessor)

                .choice()
                .when(simple("${header.mtlsEnabled} == true"))
                .process(mtlsProcessor)
                .end()

                .choice()
                .when(simple("${header.jwsEnabled} == true"))
                .process(jwsProcessor)
                .end()

                .choice()
                .when(simple("${header.jweEnabled} == true"))
                .process(jweProcessor)
                .end()

                .log("✅ Respuesta final: ${body}");
    }

     */
    @Autowired
    private IInstitutionRedisService institutionRedisService;


    @Autowired
    private RestTemplateService restTemplateService;

    @Autowired
    private WebClientService webClientService;

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
                    try {
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
                            //restTemplate = restTemplateService.getRestTemplate(institution);
                            WebClient createWebClient = webClientService.createWebClient(institution);
                            //response = restTemplate.getForEntity(institution.getEndpoint(), String.class);

                            responseBody = createWebClient
                                    .get() // método GET
                                    .uri(institution.getEndpoint()) // URL del MockMTLS
                                    .retrieve() // realiza la petición
                                    .bodyToMono(String.class) // esperamos un String
                                    .block(); // bloqueamos hasta obtener la respuesta

                        }

                        // Aplicar JWS
                        if (institution.getJws() != null && institution.getJws().isEnable()) {
                            responseBody = cryptoService.encryptData(institutionId);
                            responseBody = cryptoService.decrypt(responseBody, institution);
                        }
/*
                    // Aplicar JWE
                    if (institution.getJwe() != null && institution.getJwe().isEnable()) {
                        responseBody = securityProcessor.encrypt(responseBody, institution.getJwe());
                    }*/


                        log.info(response.getBody());
                        log.info(responseBody);

                        exchange.getMessage().setBody(responseBody);
                    }catch (Exception e) {
                        exchange.setException(e);
                    }

                });
    }

}
