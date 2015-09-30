package com.krooj.oauth.common.service;

import com.krooj.oauth.clients.domain.Client;
import com.krooj.oauth.common.domain.OAuthToken;
import com.krooj.oauth.common.domain.Scopes;
import com.krooj.oauth.common.exception.OAuthServiceException;

import java.net.URI;
import java.util.Set;

/**
 * Services used for creating OAuth and OpenID tokens.
 */
public interface TokenService {

    OAuthToken createAccessToken(Client client, String principal, Set<Scopes> authorizedScopes) throws OAuthServiceException;

    OAuthToken createRefreshToken(OAuthToken associatedAccessToken) throws OAuthServiceException;

    OAuthToken createAuthorizationCode(Client client, String principal, URI registeredRedirect, Set<Scopes> authorizedScopes) throws OAuthServiceException;

    String createOpenIdTokenWithNonce(OAuthToken oAuthToken, String nonce) throws OAuthServiceException;

    String createOpenIdToken(OAuthToken oAuthToken) throws OAuthServiceException;

}
