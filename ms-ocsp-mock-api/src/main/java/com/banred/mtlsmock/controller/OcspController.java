package com.banred.mtlsmock.controller;

import com.banred.mtlsmock.service.OcspService;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/ocsp")  // → /api/ocsp
public class OcspController {

    private final OcspService ocspService;

    public OcspController(OcspService ocspService) {
        this.ocspService = ocspService;
    }

    @GetMapping(produces = "application/ocsp-response")
    public ResponseEntity<byte[]> handleGet(
            @RequestParam(value = "request", required = false) String b64Request) {
        if (b64Request == null || b64Request.isBlank()) {
            return ResponseEntity.badRequest()
                    .body("Missing 'request' parameter".getBytes());
        }
        try {
            byte[] reqBytes = java.util.Base64.getUrlDecoder().decode(b64Request);
            return buildResponse(reqBytes);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(("Invalid Base64: " + e.getMessage()).getBytes());
        }
    }

    @PostMapping(
            consumes = "application/ocsp-request",
            produces = "application/ocsp-response"
    )
    public ResponseEntity<byte[]> handlePost(@RequestBody byte[] requestBytes) throws Exception {
        System.out.println("POST recibido: " + requestBytes.length + " bytes");

        if (requestBytes.length == 0) {
            return ResponseEntity.badRequest().body("Empty request".getBytes());
        }

        return buildResponse(requestBytes);
    }

    private ResponseEntity<byte[]> buildResponse(byte[] requestBytes) throws Exception {
        OCSPReq request = new OCSPReq(requestBytes);
        OCSPResp response = ocspService.generateResponse(request);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("application/ocsp-response"));
        headers.setCacheControl(CacheControl.noCache());

        return ResponseEntity.ok()
                .headers(headers)
                .body(response.getEncoded());
    }
}
