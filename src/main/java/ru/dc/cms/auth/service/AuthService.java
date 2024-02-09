package ru.dc.cms.auth.service;

public interface AuthService {

    public String getAuthPageUrl();

    public String getTokenRequest(String code);
}
