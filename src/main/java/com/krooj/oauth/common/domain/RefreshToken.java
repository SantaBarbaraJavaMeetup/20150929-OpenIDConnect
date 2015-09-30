package com.krooj.oauth.common.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

import java.net.URI;
import java.util.Date;
import java.util.Set;

/**
 * Created by michaelkuredjian on 9/27/15.
 */
public class RefreshToken extends OAuthToken {

    @Getter
    private final OAuthToken associatedAccessToken;

    @JsonCreator
    public RefreshToken(@JsonProperty("tokenType") TokenType tokenType,
                        @JsonProperty("audience") String audience,
                        @JsonProperty("principal") String principal,
                        @JsonProperty("redirectUri") URI redirectUri,
                        @JsonProperty("issueDate") Date issueDate,
                        @JsonProperty("expirationDate") Date expirationDate,
                        @JsonProperty("access_token") OAuthToken associatedAccessToken,
                        @JsonProperty("scopes") Set<Scopes> authorizedScopes) {
        super(tokenType, audience, principal, redirectUri, issueDate, expirationDate, authorizedScopes);
        this.associatedAccessToken = associatedAccessToken;
    }
}
