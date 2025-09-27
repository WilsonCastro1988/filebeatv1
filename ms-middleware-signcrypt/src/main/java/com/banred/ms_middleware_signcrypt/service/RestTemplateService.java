package com.banred.ms_middleware_signcrypt.service;

import org.springframework.web.client.RestTemplate;

public interface RestTemplateService {
    RestTemplate getRestTemplate(String institutionId);
}
