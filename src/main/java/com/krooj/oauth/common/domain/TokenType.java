package com.krooj.oauth.common.domain;

/**
 * Enum for the various tokens handed out by this authorization server
 */
public enum TokenType {

    AUTHORIZATION_CODE,
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    OPENID;

}
