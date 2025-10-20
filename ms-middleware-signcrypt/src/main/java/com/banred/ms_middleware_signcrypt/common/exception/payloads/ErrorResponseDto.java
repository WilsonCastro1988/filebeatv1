package com.banred.ms_middleware_signcrypt.common.exception.payloads;

import lombok.Data;

import java.util.Map;

@Data
public class ErrorResponseDto {

    private String status; // Ejemplo: FAILED
    private String error;  // Ejemplo: INVALID REQUEST
    private Map<String, String> errorDescription;

    public ErrorResponseDto() {
    }

    public ErrorResponseDto(String status, String error, Map<String, String> errorDescription) {
        this.status = status;
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public Map<String, String> getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(Map<String, String> errorDescription) {
        this.errorDescription = errorDescription;
    }
}
