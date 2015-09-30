package com.krooj.oauth.token.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

import java.util.Date;

/**
 * POJO wrapper for the access token response.
 */
public class AccessTokenResponse {

    @Getter
    @JsonProperty("token")
    private final String token;

    @Getter
    @JsonProperty("refresh_token")
    private final String refreshToken;

    @Getter
    @JsonProperty("issue_date")
    private final Date issueDate;

    private final Date expirationDate;

    @Getter
    @JsonProperty("id_token")
    private final String jwt;

    @Getter
    @JsonProperty("token_type")
    private static final String tokenType = "Bearer";

    public AccessTokenResponse(String token, String refreshToken, Date issueDate, Date expirationDate, String jwt) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.issueDate = issueDate;
        this.expirationDate = expirationDate;
        this.jwt = jwt;
    }

    @JsonProperty("expires_in")
    public long getExpirationDate() {
        return (expirationDate.getTime() - System.currentTimeMillis()) / 1000;
    }
}
