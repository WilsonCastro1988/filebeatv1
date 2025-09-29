package com.example.ms_middleware_signcrypt.model;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import lombok.Getter;
import lombok.Setter;

@XmlAccessorType(XmlAccessType.FIELD)
@Getter
@Setter
public class SecurityConfig {
    @XmlAttribute(name="enable") 
    private boolean enable;

    @XmlElement(name="keystore")
    private String keystore;

    @XmlElement(name="truststore")
    private String truststore;

    @XmlElement(name="keystorePassword")
    private String keystorePassword;

    @XmlElement(name="truststorePassword")
    private String truststorePassword;
}
