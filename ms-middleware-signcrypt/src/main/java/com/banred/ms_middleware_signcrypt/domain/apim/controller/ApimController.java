package com.banred.ms_middleware_signcrypt.domain.apim.controller;

import com.banred.ms_middleware_signcrypt.domain.apim.dto.APIMRequestDTO;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.apache.camel.ProducerTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(origins = "*")
public class ApimController {

    @Autowired
    private ProducerTemplate producerTemplate;


    @PostMapping("middleware/operation")
    public String middleware(@RequestHeader("xEntityID") String encryptedSecretKey,@NotBlank @RequestBody String payload) {

            return producerTemplate.requestBody("direct:operation_in", encryptedSecretKey, String.class);

    }

    @PostMapping("/operation")
    public String apim(@Valid @RequestBody String payload){
        try {
            return producerTemplate.requestBody("direct:operation", payload, String.class);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

}
