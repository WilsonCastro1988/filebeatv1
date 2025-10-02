package com.banred.ms_middleware_signcrypt.service;

import org.springframework.web.client.RestTemplate;

public interface RTV3Service {
    RestTemplate getRestTemplate(String institutionId);
}
