package com.banred.mtlsmock.model;

import org.springframework.http.HttpHeaders;

import java.io.Serializable;

public class ResponseMock implements Serializable {
    private String status;
    private String payload;
    private HttpHeaders headers;

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public HttpHeaders getHeaders() {
        return headers;
    }

    public void setHeaders(HttpHeaders headers) {
        this.headers = headers;
    }
}
