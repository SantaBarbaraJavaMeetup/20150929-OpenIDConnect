package com.krooj.oauth.authorization.domain;

import com.krooj.oauth.common.domain.GrantType;

import java.net.URI;

public class AuthorizationRequestBuilder {
    private GrantType grantType;
    private String clientId;
    private URI registeredRedirect;
    private String state;

    public AuthorizationRequestBuilder setGrantType(GrantType grantType) {
        this.grantType = grantType;
        return this;
    }

    public AuthorizationRequestBuilder setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public AuthorizationRequestBuilder setRegisteredRedirect(URI registeredRedirect) {
        this.registeredRedirect = registeredRedirect;
        return this;
    }

    public AuthorizationRequestBuilder setState(String state) {
        this.state = state;
        return this;
    }

    public AuthorizationRequest createAuthorizationRequest() {
        return new AuthorizationRequest(grantType, clientId, registeredRedirect, state);
    }
}