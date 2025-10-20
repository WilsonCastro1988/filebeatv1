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
}
