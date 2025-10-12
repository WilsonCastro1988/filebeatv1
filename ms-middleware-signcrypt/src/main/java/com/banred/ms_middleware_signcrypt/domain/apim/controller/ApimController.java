package com.banred.ms_middleware_signcrypt.domain.apim.controller;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.apache.camel.ProducerTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
public class ApimController {

    @Autowired
    private ProducerTemplate producerTemplate;


    @PostMapping("middleware/operation")
    public String middleware(@RequestHeader HttpHeaders headers, @NotBlank @RequestBody String payload) {
        Map<String, Object> headerMap = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            headerMap.put(entry.getKey(), entry.getValue().get(0)); // Tomar el primer valor si hay múltiples
        }
        return producerTemplate.requestBodyAndHeaders("direct:raw-api", payload, headerMap, String.class);

    }

    @PostMapping("middlewarein/operation")
    public String middlewareIN(@RequestHeader HttpHeaders headers, @NotBlank @RequestBody String payload) {
        Map<String, Object> headerMap = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            headerMap.put(entry.getKey(), entry.getValue().get(0)); // Tomar el primer valor si hay múltiples
        }
        return producerTemplate.requestBodyAndHeaders("direct:raw-api-in", payload, headerMap, String.class);

    }

    @PostMapping("/operation")
    public String apim(@Valid @RequestBody String payload, @RequestHeader HttpHeaders headers) {
        try {
            Map<String, Object> headerMap = new HashMap<>();
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                headerMap.put(entry.getKey(), entry.getValue().get(0)); // Tomar el primer valor si hay múltiples
            }
            return producerTemplate.requestBodyAndHeaders("direct:operation", payload, headerMap, String.class);
        } catch (AbstractException e) {
            throw e;
        }
    }

}
