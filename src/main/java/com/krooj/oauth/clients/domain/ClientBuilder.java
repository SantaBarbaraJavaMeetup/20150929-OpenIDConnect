package com.krooj.oauth.clients.domain;

import com.krooj.oauth.common.domain.GrantType;
import com.krooj.oauth.common.domain.Scopes;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;

public class ClientBuilder {
    private String clientId;
    private String clientSecret;
    private String clientName;
    private Set<URI> registeredRedirects;
    private Set<GrantType> authorizedGrantTypes;
    private Set<String> clientRoles;
    private Set<Scopes> eligibleScopes;


    public ClientBuilder setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public ClientBuilder setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public ClientBuilder setClientRoles(Set<String> roles) {
        this.clientRoles = roles;
        return this;
    }

    public ClientBuilder addRole(String role) {
        if (this.clientRoles == null) {
            this.clientRoles = new HashSet<>();
        }
        this.clientRoles.add(role);
        return this;
    }

    public ClientBuilder setClientName(String clientName) {
        this.clientName = clientName;
        return this;
    }

    public ClientBuilder setRegisteredRedirects(Set<URI> registeredRedirects) {
        this.registeredRedirects = registeredRedirects;
        return this;
    }

    public ClientBuilder setAuthorizedGrantType(Set<GrantType> authorizedGrantTypes) {
        this.authorizedGrantTypes = authorizedGrantTypes;
        return this;
    }

    public ClientBuilder setEligibleScopes(Set<Scopes> eligibleScopes) {
        this.eligibleScopes = eligibleScopes;
        return this;
    }

    public Client createClient() {
        return new Client(clientId, clientSecret, clientName, registeredRedirects, authorizedGrantTypes, clientRoles, eligibleScopes);
    }
}