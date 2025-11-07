package com.banred.ms_middleware_signcrypt.common.exception.payloads;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Setter
@Getter
@Data
public class ErrorResponseDto {

    private String status;
    private String error;
    private Map<String, String> errorDescription;

    public ErrorResponseDto() {
    }

    public ErrorResponseDto(String status, String error, Map<String, String> errorDescription) {
        this.status = status;
        this.error = error;
        this.errorDescription = errorDescription;
    }

}
