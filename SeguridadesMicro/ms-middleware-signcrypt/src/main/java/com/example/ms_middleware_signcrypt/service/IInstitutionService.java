package com.example.ms_middleware_signcrypt.service;

import com.example.ms_middleware_signcrypt.model.Institution;
import com.example.ms_middleware_signcrypt.model.Institutions;

public interface IInstitutionService {
    void loadInstitutions();
    
    Institutions getInstitutions();

    Institution getInstitutionById(String id);
}
