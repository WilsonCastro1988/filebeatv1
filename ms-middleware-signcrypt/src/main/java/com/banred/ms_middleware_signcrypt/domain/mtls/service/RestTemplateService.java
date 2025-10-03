package com.banred.ms_middleware_signcrypt.domain.mtls.service;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

public interface RestTemplateService {
    RestTemplate getRestTemplate(Institution institution);
    }
