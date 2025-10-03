package com.banred.ms_middleware_signcrypt.domain.institution.service;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institutions;
import com.fasterxml.jackson.core.JsonProcessingException;

public interface IInstitutionRedisService {
    public void saveInstitutions(Institutions institutions);
    public Institution getInstitution(String id) throws JsonProcessingException;
}
