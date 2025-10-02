package com.banred.ms_middleware_signcrypt.service;

import org.springframework.web.client.RestTemplate;

public interface RestTemplateService2 {
    RestTemplate getRestTemplate(String institutionId);
}
