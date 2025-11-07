package com.banred.ms_middleware_signcrypt.domain.institution.model.dto;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@XmlAccessorType(XmlAccessType.FIELD)
public class Endpoint {
    @XmlAttribute(name = "tipo")
    private String tipo;

    @XmlAttribute(name = "url")
    private String url;
}
