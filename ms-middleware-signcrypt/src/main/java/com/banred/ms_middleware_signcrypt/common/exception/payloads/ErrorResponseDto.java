package com.banred.ms_middleware_signcrypt.common.exception.payloads;

import lombok.Data;

import java.util.Map;

@Data
public class ErrorResponseDto {

    private String status; // Ejemplo: FAILED
    private String error;  // Ejemplo: INVALID REQUEST
    private Map<String, String> error_description;

    public ErrorResponseDto() {
    }

    public ErrorResponseDto(String status, String error, Map<String, String> error_description) {
        this.status = status;
        this.error = error;
        this.error_description = error_description;
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

    public Map<String, String> getError_description() {
        return error_description;
    }

    public void setError_description(Map<String, String> error_description) {
        this.error_description = error_description;
    }
}
