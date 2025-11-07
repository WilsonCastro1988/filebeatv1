package com.banred.mtlsmock.controller;

import com.banred.mtlsmock.service.OcspService;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/ocsp")
public class OcspController {

    private final OcspService ocspService;

    public OcspController(OcspService ocspService) {
        this.ocspService = ocspService;
    }

    /**
     * Maneja peticiones OCSP tipo GET (Base64 URL encoded)
     */
    @GetMapping
    public ResponseEntity<byte[]> handleGet(@RequestParam("request") String b64Request) {
        try {
            byte[] reqBytes = java.util.Base64.getUrlDecoder().decode(b64Request);
            return buildResponse(reqBytes);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(("Invalid OCSP GET: " + e.getMessage()).getBytes());
        }
    }

    /**
     * Maneja peticiones OCSP tipo POST (DER binario)
     */
    @PostMapping(
            consumes = { "application/ocsp-request", MediaType.APPLICATION_OCTET_STREAM_VALUE },
            produces = "application/ocsp-response"
    )
    public ResponseEntity<byte[]> handlePost(@RequestBody byte[] request) {
        try {
            return buildResponse(request);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest()
                    .body(("Invalid OCSP POST: " + e.getMessage()).getBytes());
        }
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
