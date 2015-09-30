package com.krooj.oauth.common.service;

import com.krooj.oauth.common.domain.GrantType;
import com.krooj.oauth.common.domain.Scopes;
import com.krooj.oauth.token.domain.AccessTokenResponse;

import java.net.URI;
import java.util.List;

/**
 * Common service layer for this authorization server
 */
public interface OAuthService {


    /**
     * Creates an authorization request and returns a full {@link URI} with the authorization code
     * encoded.
     *
     * @param clientId           A valid ID of a client that was registered with this authorization server
     * @param registeredRedirect A valid registered redirect for the aforementioned client
     * @param state              Any state which needs to be coded back on the redirect.
     * @param requestedScopes    What the client is asking for access to.
     * @return A {@link URI} with the ?code=&state=
     */
    URI createAuthorizationRequest(String clientId, String principal, URI registeredRedirect, String state, List<Scopes> requestedScopes);

    /**
     * Creates the token response expected from an implicit request.
     *
     * @param clientId
     * @param principal
     * @param registeredRedirect
     * @param state
     * @param requestedScopes
     * @param openid
     * @param nonce
     * @return
     */
    URI createImplicitAuthorization(String clientId, String principal, URI registeredRedirect, String state, List<Scopes> requestedScopes, boolean openid, String nonce);

    /**
     * The process of exchanging the authorization code for an access token completes the three legged authorization code grant flow
     * for OAuth 2.0. The following conditions must be met for the authorization code to be successfully exchanged for an access token:
     * <ul>
     * <li>The authorization code must not be expired</li>
     * <li>The redirect URI from the authorization code must match the one from the authorization request</li>
     * <li>The grant type must be {@link GrantType#authorization_code}</li>
     * <li>The client ID must match the one from the authorization request</li>
     * </ul>
     *
     * @param authorizationCode
     * @param grantType
     * @param clientId
     * @param registeredRedirect
     * @return {@link AccessTokenResponse}
     */
    AccessTokenResponse exchangeAuthorizationCodeForToken(String authorizationCode, GrantType grantType, String clientId, URI registeredRedirect);
}
