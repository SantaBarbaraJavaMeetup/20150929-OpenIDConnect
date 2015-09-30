package com.krooj.oauth.common.service;

import com.krooj.oauth.clients.domain.Client;
import com.krooj.oauth.clients.service.ClientService;
import com.krooj.oauth.common.datamapper.TokenEvictionDM;
import com.krooj.oauth.common.domain.GrantType;
import com.krooj.oauth.common.domain.OAuthToken;
import com.krooj.oauth.common.domain.Scopes;
import com.krooj.oauth.common.domain.TokenType;
import com.krooj.oauth.common.exception.OAuthServiceException;
import com.krooj.oauth.common.util.CryptoUtil;
import com.krooj.oauth.common.util.InputValidationUtils;
import com.krooj.oauth.token.domain.AccessTokenResponse;
import com.krooj.oauth.token.domain.AccessTokenResponseBuilder;
import lombok.extern.log4j.Log4j2;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.transaction.Transactional;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;

/**
 * Concrete implementation of the {@link OAuthService}
 */
@Service
@Transactional(rollbackOn = {OAuthServiceException.class})
@Log4j2
public class OAuthServiceImpl implements OAuthService {

    private final ClientService clientService;

    private final TokenService tokenService;

    private final TokenEvictionDM tokenEvictionDM;

    @Autowired
    public OAuthServiceImpl(ClientService clientService, TokenService tokenService, TokenEvictionDM tokenEvictionDM) {
        this.clientService = clientService;
        this.tokenService = tokenService;
        this.tokenEvictionDM = tokenEvictionDM;
    }

    @Override
    public URI createAuthorizationRequest(String clientId, String principal, URI registeredRedirect, String state, List<Scopes> requestedScopes) {

        //Validate method inputs.
        InputValidationUtils.assertHasText(clientId, "error.client.id.empty");
        InputValidationUtils.assertHasText(principal, "error.principal.empty");
        InputValidationUtils.assertNotNull(registeredRedirect, "error.redirect.null");
        InputValidationUtils.assertNotNull(requestedScopes, "error.scopes.null");

        //Get the client
        Client requestingClient = clientService.retrieveClientById(clientId);

        //Ensure the requesting client has this grant type
        if (!requestingClient.isGrantAuthorized(GrantType.authorization_code)) {
            throw new OAuthServiceException("error.client.grant.missing");
        }
        if (!requestingClient.isEligibleForRequestedScopes(requestedScopes)) {
            throw new OAuthServiceException("error.client.scopes.invalid");
        }
        //Ensure that the redirect is valid for the target client
        if (!requestingClient.checkRedirectValidForClient(registeredRedirect)) {
            throw new OAuthServiceException("error.client.redirect");
        }

        OAuthToken authorizationCodeToken = tokenService.createAuthorizationCode(requestingClient, principal, registeredRedirect, new HashSet<>(requestedScopes));
        return buildRedirect(registeredRedirect, CryptoUtil.getInstance().tokenToBase64CipherText(authorizationCodeToken), state);
    }

    @Override
    public URI createImplicitAuthorization(String clientId, String principal, URI registeredRedirect, String state, List<Scopes> requestedScopes, boolean openid, String nonce) {

        //Validate method inputs.
        InputValidationUtils.assertHasText(clientId, "error.client.id.empty");
        InputValidationUtils.assertHasText(principal, "error.principal.empty");
        InputValidationUtils.assertNotNull(registeredRedirect, "error.redirect.null");
        InputValidationUtils.assertNotNull(requestedScopes, "error.scopes.null");

        //Get the client
        Client requestingClient = clientService.retrieveClientById(clientId);

        //Ensure the requesting client has this grant type
        if (!requestingClient.isGrantAuthorized(GrantType.implicit)) {
            throw new OAuthServiceException("error.client.grant.missing");
        }
        if (!requestingClient.isEligibleForRequestedScopes(requestedScopes)) {
            throw new OAuthServiceException("error.client.scopes.invalid");
        }
        //Ensure that the redirect is valid for the target client
        if (!requestingClient.checkRedirectValidForClient(registeredRedirect)) {
            throw new OAuthServiceException("error.client.redirect");
        }

        OAuthToken accessToken = tokenService.createAccessToken(requestingClient, principal, new HashSet<>(requestedScopes));
        String openIdJwt = null;
        if (openid && accessToken.getAuthorizedScopes().contains(Scopes.openid)) {
            openIdJwt = tokenService.createOpenIdTokenWithNonce(accessToken, nonce);
        }
        return buildImplicitRedirect(registeredRedirect, CryptoUtil.getInstance().tokenToBase64CipherText(accessToken), accessToken.getExpirationDate().getTime(), openIdJwt, state);

    }

    @Override
    public AccessTokenResponse exchangeAuthorizationCodeForToken(String authorizationCode, GrantType grantType, String clientId, URI registeredRedirect) {

        //Validate method inputs
        InputValidationUtils.assertHasText(authorizationCode, "error.token.empty");
        InputValidationUtils.assertNotNull(grantType, "error.granttype.null");
        InputValidationUtils.assertHasText(clientId, "error.client.id.empty");
        InputValidationUtils.assertNotNull(registeredRedirect, "error.redirect.null");

        try {
            authorizationCode = URLDecoder.decode(authorizationCode, StandardCharsets.UTF_8.displayName());
        } catch (UnsupportedEncodingException e) {
            throw new OAuthServiceException("error.authorization.encoding.unsupported", e);
        }

        //Get the token
        OAuthToken authorizationCodeToken = (OAuthToken) CryptoUtil.getInstance().base64CipherTexttoToken(authorizationCode, TokenType.AUTHORIZATION_CODE);

        //Retrieve the client
        Client requestingClient = clientService.retrieveClientById(clientId);

        //Validate
        if (tokenEvictionDM.isTokenConsumed(authorizationCode)) {
            throw new OAuthServiceException("error.authorization.code.invalid");
        }
        if (!GrantType.authorization_code.equals(grantType) && !GrantType.implicit.equals(grantType)) {
            throw new OAuthServiceException("error.authorization.grant.mismatch");
        }
        if (!authorizationCodeToken.isNonExpired()) {
            throw new OAuthServiceException("error.authorization.code.expired");
        }
        if (!clientId.equals(authorizationCodeToken.getAudience())) {
            throw new OAuthServiceException("error.authorization.code.client.mismatch");
        }
        if (!authorizationCodeToken.getRedirectUri().equals(registeredRedirect)) {
            throw new OAuthServiceException("error.authorization.code.redirect.mismatch");
        }

        //Create the access token
        OAuthToken accessToken = tokenService.createAccessToken(requestingClient, authorizationCodeToken.getPrincipal(), authorizationCodeToken.getAuthorizedScopes());
        String cipheredAccessToken = CryptoUtil.getInstance().tokenToBase64CipherText(accessToken);

        //Mark the authorization code as consumed
        tokenEvictionDM.markTokenAsConsumed(authorizationCode);

        AccessTokenResponseBuilder responseBuilder = new AccessTokenResponseBuilder();
        responseBuilder.setToken(cipheredAccessToken)
                .setExpirationDate(accessToken.getExpirationDate())
                .setIssueDate(accessToken.getIssueDate());

        //Create a refresh token if needed
        if (requestingClient.isGrantAuthorized(GrantType.refresh)) {
            String cipheredRefreshToken = CryptoUtil.getInstance().tokenToBase64CipherText(tokenService.createRefreshToken(accessToken));
            responseBuilder.setRefreshToken(cipheredRefreshToken);
        }

        //Generate the OpenID JWT
        if (accessToken.getAuthorizedScopes().contains(Scopes.openid)) {
            String jwt = tokenService.createOpenIdToken(accessToken);
            responseBuilder.setJwt(jwt);
        }

        return responseBuilder.createAccessTokenResponse();
    }

    private URI buildRedirect(URI registeredRedirect, String tokenValue, String state) {
        try {
            URIBuilder uriBuilder = new URIBuilder(registeredRedirect);
            uriBuilder.addParameter("code", tokenValue);
            if (StringUtils.hasText(state)) {
                uriBuilder.addParameter("state", state);
            }
            return uriBuilder.build();
        } catch (URISyntaxException e) {
            throw new OAuthServiceException("error.registeredredirect", e);
        }
    }

    private URI buildImplicitRedirect(URI registeredRedirect, String tokenValue, long expirationDate, String openIdJwt, String state) {
        try {
            URIBuilder uriBuilder = new URIBuilder(registeredRedirect);
            uriBuilder.addParameter("access_token", tokenValue);
            uriBuilder.addParameter("token_type", "bearer");
            if (StringUtils.hasText(openIdJwt)) {
                uriBuilder.addParameter("id_token", openIdJwt);
            }
            uriBuilder.addParameter("expires_in", Long.toString((expirationDate - System.currentTimeMillis()) / 1000));
            if (StringUtils.hasText(state)) {
                uriBuilder.addParameter("state", state);
            }
            return uriBuilder.build();
        } catch (URISyntaxException e) {
            throw new OAuthServiceException("error.registeredredirect", e);
        }
    }
}
