package com.krooj.oauth.common.domain;

/**
 * Codifies the supported grant types
 */
public enum GrantType {

    authorization_code,
    implicit,
    resource_owner,
    client_credentials,
    refresh;

}
