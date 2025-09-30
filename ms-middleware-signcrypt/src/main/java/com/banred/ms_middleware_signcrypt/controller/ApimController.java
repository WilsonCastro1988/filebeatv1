package com.banred.ms_middleware_signcrypt.controller;

import org.apache.camel.ProducerTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(origins = "*")
public class ApimController {

    @Autowired
    private ProducerTemplate producerTemplate;

    @PostMapping("apim")
    public String handleApimRequest(@RequestBody String id) {
        try {
            return producerTemplate.requestBody("direct:secureInstitutionCall", id, String.class);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

}
