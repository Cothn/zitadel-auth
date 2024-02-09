package ru.dc.cms.auth.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import ru.dc.cms.auth.model.zitadel.ParameterKeys;
import ru.dc.cms.auth.service.AuthService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.StringJoiner;

@Slf4j
@Service
public class ZitadelAuthService implements AuthService, ParameterKeys {

    private String CODE_CHALLENGE_METHOD_VALUE = "S256";
    private String authRequestUrl = "/oauth/v2/authorize";

    public String hostURI;
    public String clientId;
    public String authorizationGrantType;
    public String responseType;
    public String redirectURI;
    public List<String> scope;

    private String codeVerifier;
    private String codeChallenge;


    public ZitadelAuthService(@Value("${auth.oauth2.client.provider.zitadel.issuer-uri}") String zitadelURI,
                              @Value("${auth.oauth2.client.registration.zitadel.client-id}") String clientId,
                              @Value("${auth.oauth2.client.registration.zitadel.authorizationGrantType}") String authorizationGrantType,
                              @Value("${auth.oauth2.client.registration.zitadel.response-type}") String responseType,
                              @Value("${auth.oauth2.client.registration.zitadel.redirect-uri}") String redirectURI,
                              @Value("${auth.oauth2.client.registration.zitadel.scope}") List<String> scope) throws NoSuchAlgorithmException {

        this.hostURI = zitadelURI;
        this.clientId = clientId;
        this.authorizationGrantType = authorizationGrantType;
        this.responseType = responseType;
        this.redirectURI = redirectURI;
        this.scope = scope;
        this.codeVerifier = generateCodeVerifier(32);
        this.codeChallenge = generateCodeChallenge();
    }

    public String generateCodeVerifier(int length) {
        int leftLimit = 32;
        int rightLimit = 126;

        Random random = new Random();
        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .limit(length)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        return generatedString;
    }

    public String generateCodeChallenge() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String codeChallengeString = Base64.getEncoder().encodeToString(digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8)));
        return codeChallengeString;
    }

    public String getScopeQuery(){
        StringJoiner joiner = new StringJoiner(" ");
        scope.forEach(joiner::add);
        return joiner.toString();
    }

    @Override
    public String getAuthPageUrl() {
        String authPageUrl = UriComponentsBuilder.fromUriString(hostURI + authRequestUrl)
                .queryParam(ParameterKeys.CLIENT_ID, clientId)
                .queryParam(ParameterKeys.REDIRECT_URI, redirectURI)
                .queryParam(ParameterKeys.RESPONSE_TYPE, responseType)
                .queryParam(ParameterKeys.SCOPE, getScopeQuery())
                .queryParam(ParameterKeys.CODE_CHALLENGE, codeChallenge)
                .queryParam(ParameterKeys.CODE_CHALLENGE_METHOD, CODE_CHALLENGE_METHOD_VALUE)
                .build()
                .toUriString();

        return authPageUrl;
    }
}
