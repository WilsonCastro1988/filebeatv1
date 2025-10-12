package com.banred.ms_middleware_signcrypt.domain.jw.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JWSResponse {
    private String jwsCompact;
    private String digestHeader;
    private String signatureInput;
    private String signatureHeader;

    /*
    public String getJwsCompact() {
        return jwsCompact;
    }

    public void setJwsCompact(String jwsCompact) {
        this.jwsCompact = jwsCompact;
    }

    public String getDigestHeader() {
        return digestHeader;
    }

    public void setDigestHeader(String digestHeader) {
        this.digestHeader = digestHeader;
    }

    public String getSignatureInput() {
        return signatureInput;
    }

    public void setSignatureInput(String signatureInput) {
        this.signatureInput = signatureInput;
    }

    public String getSignatureHeader() {
        return signatureHeader;
    }

    public void setSignatureHeader(String signatureHeader) {
        this.signatureHeader = signatureHeader;
    }

     */
}
