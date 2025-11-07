package com.banred.ms_middleware_signcrypt.domain.institution.service;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institutions;

public interface IInstitutionService {
    void loadInstitutions();

    Institutions getInstitutions();
}
