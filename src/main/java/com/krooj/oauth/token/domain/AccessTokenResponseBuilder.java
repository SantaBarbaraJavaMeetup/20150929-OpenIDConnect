package com.krooj.oauth.token.domain;

import java.util.Date;

public class AccessTokenResponseBuilder {
    private String token;
    private String refreshToken;
    private Date issueDate;
    private Date expirationDate;
    private String jwt;

    public AccessTokenResponseBuilder setToken(String token) {
        this.token = token;
        return this;
    }

    public AccessTokenResponseBuilder setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
        return this;
    }

    public AccessTokenResponseBuilder setIssueDate(Date issueDate) {
        this.issueDate = issueDate;
        return this;
    }

    public AccessTokenResponseBuilder setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
        return this;
    }

    public AccessTokenResponseBuilder setJwt(String jwt) {
        this.jwt = jwt;
        return this;
    }

    public AccessTokenResponse createAccessTokenResponse() {
        return new AccessTokenResponse(token, refreshToken, issueDate, expirationDate, jwt);
    }
}