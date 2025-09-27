package com.banred.ms_middleware_signcrypt.service;

import com.banred.ms_middleware_signcrypt.model.Institution;
import com.banred.ms_middleware_signcrypt.model.Institutions;

public interface IInstitutionService {
    void loadInstitutions();
    
    Institutions getInstitutions();

    Institution getInstitutionById(String id);
}
