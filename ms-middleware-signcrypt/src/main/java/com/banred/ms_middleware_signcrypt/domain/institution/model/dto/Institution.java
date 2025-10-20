package com.banred.ms_middleware_signcrypt.domain.institution.model.dto;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import lombok.Getter;
import lombok.Setter;

@XmlAccessorType(XmlAccessType.FIELD)
@Getter
@Setter
public class Institution {
    @XmlAttribute(name="id")
    private String id;

    @XmlElement(name="name")
    private String name;

    @XmlElement(name="tls")
    private boolean  tls;

    @XmlElement(name="timeout")
    private int timeout;

    @XmlElement(name="endpoint")
    private String endpoint;

    @XmlElement(name="mtls")
    private SecurityConfig mtls;

    @XmlElement(name="jws")
    private SecurityConfig jws;

    @XmlElement(name="jwe")
    private SecurityConfig jwe;

}
