package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.route;

import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

@Component
public class OpRoute extends RouteBuilder {
    @Override
    public void configure() throws Exception {

    }

    /*
    @Autowired
    private IInstitutionRedisService institutionRedisService;

    @Autowired
    private RestTemplateService restTemplateService;

    @Autowired
    private CryptoService cryptoService;

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
                        restTemplate = restTemplateService.getRestTemplate(institution);
                        response = restTemplate.getForEntity(institution.getEndpoint(), String.class);
                    }

                    // Aplicar JWS
                    if (institution.getJws() != null && institution.getJws().isEnable()) {
                        responseBody = cryptoService.encryptData(institutionId);
                        responseBody = cryptoService.decrypt(responseBody, institution);
                    }

                    // Aplicar JWE
                    if (institution.getJwe() != null && institution.getJwe().isEnable()) {
                        responseBody = cryptoService.encrypt(responseBody, institution);
                    }


                    log.info(response.getBody());
                    log.info(responseBody);

                    exchange.getMessage().setBody(responseBody);
                });
    }

     */
/*

    @Autowired
    private InstitutionLookupProcessor institutionLookupProcessor;
    @Autowired
    private MtlsProcessor mtlsRequestProcessor;
    @Autowired
    private JwsProcessor jwsProcessor;
    @Autowired
    private JweProcessor jweProcessor;
    @Autowired
    private ResponseProcessor responseProcessor;

    @Override
    public void configure() {
       /* from("direct:operation_out")
                .routeId("operation_out")
                .log("🔐 Iniciando procesamiento para institución: ${body}")
                .process(institutionLookupProcessor)
                .choice()
                .when(simple("${exchangeProperty.institution.mtls.enable} == true"))
                .process(mtlsRequestProcessor)
                .end()
                .choice()
                .when(simple("${exchangeProperty.institution.jws.enable} == true"))
                .process(jwsProcessor)
                .end()
                .choice()
                .when(simple("${exchangeProperty.institution.jwe.enable} == true"))
                .process(jweProcessor)
                .end()
                .process(responseProcessor)
                .log("✅ Procesamiento completo: ${body}");



    }

 */



}
