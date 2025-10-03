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

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isTls() {
        return tls;
    }

    public void setTls(boolean tls) {
        this.tls = tls;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public SecurityConfig getMtls() {
        return mtls;
    }

    public void setMtls(SecurityConfig mtls) {
        this.mtls = mtls;
    }

    public SecurityConfig getJws() {
        return jws;
    }

    public void setJws(SecurityConfig jws) {
        this.jws = jws;
    }

    public SecurityConfig getJwe() {
        return jwe;
    }

    public void setJwe(SecurityConfig jwe) {
        this.jwe = jwe;
    }
}
