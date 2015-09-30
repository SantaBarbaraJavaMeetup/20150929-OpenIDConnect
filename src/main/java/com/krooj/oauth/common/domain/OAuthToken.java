package com.krooj.oauth.common.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

import java.net.URI;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

/**
 * Implementation of the {@link Token} which is specific to OAuth2 bearers
 */
public class OAuthToken extends Token {

    @Getter
    private final String tokenValue;

    @Getter
    private final URI redirectUri;

    @Getter
    private final Set<Scopes> authorizedScopes;

    @JsonCreator
    public OAuthToken(@JsonProperty("tokenType") TokenType tokenType,
                      @JsonProperty("audience") String audience,
                      @JsonProperty("principal") String principal,
                      @JsonProperty("redirectUri") URI redirectUri,
                      @JsonProperty("issueDate") Date issueDate,
                      @JsonProperty("expirationDate") Date expirationDate,
                      @JsonProperty("scopes") Set<Scopes> authorizedScopes) {
        super(tokenType, audience, principal, issueDate, expirationDate);
        this.redirectUri = redirectUri;
        this.authorizedScopes = authorizedScopes;
        this.tokenValue = UUID.randomUUID().toString();
    }

    @Override
    public String toString() {
        return getTokenValue();
    }
}
