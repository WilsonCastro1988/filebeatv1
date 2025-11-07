package com.banred.mtlsmock.controller;

import com.banred.mtlsmock.model.ResponseMock;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/secure")
public class SecureMockController {

    @PostMapping(value = "/mtlsi")
    public ResponseEntity<String> postMtlsi(@RequestBody String payload, @RequestHeader HttpHeaders headers) {
        return construirRespuesta("✅ RESPONSE OPERACION OPCION I : INQUERY", payload, headers);
    }

    @PostMapping("/mtlst")
    public ResponseEntity<String> postMtlst(@RequestBody String payload, @RequestHeader HttpHeaders headers) {
        return construirRespuesta("✅ RESPONSE OPERACION OPCION T: TRANSACTION/TRANSFER", payload, headers);
    }

    @PostMapping("/mtlsn")
    public ResponseEntity<String> postMtlsn(@RequestBody String payload, @RequestHeader HttpHeaders headers) {
        return construirRespuesta("✅ RESPONSE OPERACION OPCION N: NOTIFICATION", payload, headers);
    }

    @PostMapping("/mtlse")
    public ResponseEntity<String> postMtlse(@RequestBody String payload, @RequestHeader HttpHeaders headers) {
        return construirRespuesta("✅ RESPONSE OPERACION OPCION E: ENROLLMENT", payload, headers);
    }

    @PostMapping("/mtlsde")
    public ResponseEntity<String> postMtlsde(@RequestBody String payload, @RequestHeader HttpHeaders headers) {
        return construirRespuesta("✅ RESPONSE OPERACION OPCION DE: DISENROLLMENT", payload, headers);
    }
    @PostMapping("/mtlsma")
    public ResponseEntity<String> postMtlsma(@RequestBody String payload, @RequestHeader HttpHeaders headers) {
        return construirRespuesta("✅ RESPONSE OPERACION OPCION MA: MODIFY ALIAS", payload, headers);
    }

    public ResponseEntity<String> construirRespuesta(String status, String payload, HttpHeaders headers) {
        ObjectMapper mapper = new ObjectMapper();

        ResponseMock responseMock = new ResponseMock();
        responseMock.setStatus(status);
        responseMock.setPayload(payload);
        responseMock.setHeaders(headers);

        String jsonResponse = null;
        try {
            jsonResponse = mapper.writeValueAsString(responseMock);
        } catch (JsonProcessingException e) {
            jsonResponse = "✅ FAIL from MockTls XD";
        }

        return ResponseEntity
                .ok(jsonResponse);
    }

}

