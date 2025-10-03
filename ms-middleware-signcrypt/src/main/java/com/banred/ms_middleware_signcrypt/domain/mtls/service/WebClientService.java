package com.banred.ms_middleware_signcrypt.domain.mtls.service;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import org.springframework.web.reactive.function.client.WebClient;

public interface WebClientService {
     WebClient createWebClient(Institution institution) ;
    }
