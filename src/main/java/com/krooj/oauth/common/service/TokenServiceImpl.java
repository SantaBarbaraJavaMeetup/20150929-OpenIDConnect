package com.krooj.oauth.common.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.krooj.oauth.clients.domain.Client;
import com.krooj.oauth.common.domain.*;
import com.krooj.oauth.common.exception.OAuthServiceException;
import com.krooj.oauth.common.util.InputValidationUtils;
import lombok.extern.log4j.Log4j2;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.util.Date;
import java.util.Set;

/**
 * Default implementation of the {@link TokenService}
 */
@Service
@Log4j2
public class TokenServiceImpl implements TokenService {

    private final ObjectMapper objectMapper;

    @Autowired
    public TokenServiceImpl(ObjectMapper objectMapper) throws OAuthServiceException {
        this.objectMapper = objectMapper;
    }

    @Override
    public OAuthToken createAccessToken(Client client, String principal, Set<Scopes> authorizedScopes) throws OAuthServiceException {
        Date issueDate = new Date();
        Date expirationDate = Token.assignExpiration(TokenType.ACCESS_TOKEN, issueDate);
        return new OAuthToken(TokenType.ACCESS_TOKEN, client.getClientId(), principal, null, issueDate, expirationDate, authorizedScopes);
    }

    @Override
    public OAuthToken createRefreshToken(OAuthToken associatedAccessToken) throws OAuthServiceException {
        Date issueDate = associatedAccessToken.getIssueDate();
        Date expirationDate = Token.assignExpiration(TokenType.REFRESH_TOKEN, issueDate);
        return new RefreshToken(TokenType.REFRESH_TOKEN, associatedAccessToken.getAudience(), associatedAccessToken.getPrincipal(), null, issueDate, expirationDate, associatedAccessToken, associatedAccessToken.getAuthorizedScopes());
    }

    @Override
    public OAuthToken createAuthorizationCode(Client client, String principal, URI registeredRedirect, Set<Scopes> authorizedScopes) throws OAuthServiceException {
        Date issueDate = new Date();
        Date expirationDate = Token.assignExpiration(TokenType.AUTHORIZATION_CODE, issueDate);
        return new OAuthToken(TokenType.AUTHORIZATION_CODE, client.getClientId(), principal, registeredRedirect, issueDate, expirationDate, authorizedScopes);

    }

    @Override
    public String createOpenIdTokenWithNonce(OAuthToken oAuthToken, String nonce) throws OAuthServiceException {
        InputValidationUtils.assertHasText(nonce, "error.tokenservices.nonce.empty");
        return createOpenIdTokenInternal(oAuthToken, nonce);
    }

    @Override
    public String createOpenIdToken(OAuthToken oAuthToken) throws OAuthServiceException {
        return createOpenIdTokenInternal(oAuthToken, null);
    }

    private String createOpenIdTokenInternal(OAuthToken oAuthToken, String nonce) {
        //Perform some input validation
        InputValidationUtils.assertNotNull(oAuthToken, "error.tokenservices.token.null");
        if (!TokenType.ACCESS_TOKEN.equals(oAuthToken.getTokenType())) {
            throw new OAuthServiceException("error.tokenservices.openid.accesstoken.bad");
        }

        RsaJsonWebKey rsaJsonWebKey = null;
        try {
            rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
            rsaJsonWebKey.setKeyId("k1");
            JwtClaims claims = new JwtClaims();
            claims.setIssuer("com.krooj.oauth.authorization-server");  // who creates the token and signs it
            claims.setAudience(oAuthToken.getAudience()); // to whom the token is intended to be sent
            claims.setExpirationTime(NumericDate.fromMilliseconds(oAuthToken.getExpirationDate().getTime()));
            claims.setGeneratedJwtId(); // a unique identifier for the token
            claims.setIssuedAtToNow();  // when the token was issued/created (now)
            claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
            claims.setSubject(oAuthToken.getPrincipal()); // the subject/principal is whom the token is about
            claims.setClaim("isPotato", "yes"); // additional claims/attributes about the subject can be added
            if (StringUtils.hasText(nonce)) {
                claims.setClaim("nonce", nonce);
            }

            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toJson());
            jws.setKey(rsaJsonWebKey.getPrivateKey());
            jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
            String jwt = jws.getCompactSerialization();

            log.info("op=createOpenIdToken jwt={}", jwt);

            return jwt;
        } catch (JoseException e) {
            throw new OAuthServiceException("error.tokenservices.openid.creation", e);
        }
    }
}
