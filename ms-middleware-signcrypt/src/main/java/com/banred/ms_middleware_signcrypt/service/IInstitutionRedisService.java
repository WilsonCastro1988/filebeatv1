package com.banred.ms_middleware_signcrypt.service;

import com.banred.ms_middleware_signcrypt.model.Institution;
import com.banred.ms_middleware_signcrypt.model.Institutions;
import com.fasterxml.jackson.core.JsonProcessingException;

public interface IInstitutionRedisService {
    public void saveInstitutions(Institutions institutions);
    public Institution getInstitution(String id) throws JsonProcessingException;
}
