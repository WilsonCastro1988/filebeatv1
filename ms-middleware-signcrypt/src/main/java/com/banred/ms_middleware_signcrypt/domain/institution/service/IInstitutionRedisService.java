package com.banred.ms_middleware_signcrypt.domain.institution.service;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institutions;
import com.fasterxml.jackson.core.JsonProcessingException;

public interface IInstitutionRedisService {
    void saveInstitutions(Institutions institutions);
    Institution getInstitution(String id) throws JsonProcessingException;
}
