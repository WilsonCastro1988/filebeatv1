package com.banred.ms_middleware_signcrypt.domain.apim.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.apache.camel.ProducerTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.*;

import static com.banred.ms_middleware_signcrypt.common.util.Utilities.obtenerHeaders;

@RestController
@CrossOrigin(origins = "*")
public class ApimController {


    private final ProducerTemplate producerTemplate;

    public ApimController(ProducerTemplate producerTemplate) {
        this.producerTemplate = producerTemplate;
    }

    @PostMapping("middleware/operation")
    public String middleware(@RequestHeader HttpHeaders headers, @NotBlank @RequestBody String payload) {
        return producerTemplate.requestBodyAndHeaders("direct:middleware", payload, obtenerHeaders(headers), String.class);
    }

    @PostMapping("/operation")
    public String apim(@Valid @RequestBody String payload, @RequestHeader HttpHeaders headers) {
        return producerTemplate.requestBodyAndHeaders("direct:operation", payload, obtenerHeaders(headers), String.class);
    }

}
