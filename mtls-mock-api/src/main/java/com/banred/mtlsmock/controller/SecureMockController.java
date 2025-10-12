package com.banred.mtlsmock.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/secure")
public class SecureMockController {

    @GetMapping("/mtls")
    public ResponseEntity<String> getMtls(Principal principal) {
        return ResponseEntity.ok("✅ Hi from MockTls XD  " + principal.getName() +
                ", conexión mTLS establecida con éxito!");
    }

    @PostMapping("/mtls")
    public ResponseEntity<Map<String, Object>> postMtls(@RequestBody String payload, @RequestHeader HttpHeaders headers) {
        try {
            Map<String, Object> response = new HashMap<>();

            Map<String, String> headerMap = new HashMap<>();
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                headerMap.put(entry.getKey(), entry.getValue().get(0)); // Tomar el primer valor si hay múltiples
            }

            // Construir respuesta estructurada
            response.put("status", "✅ Hi AGAIN from MockTls!");
            response.put("payload", payload);
            response.put("headers", headerMap);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "✅ FAIL from MockTls XD");
            errorResponse.put("error", e.getMessage());
            return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
        }
    }

}

