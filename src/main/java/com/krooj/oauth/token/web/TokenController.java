package com.krooj.oauth.token.web;

import com.krooj.oauth.clients.domain.Client;
import com.krooj.oauth.common.domain.GrantType;
import com.krooj.oauth.common.exception.OAuthServiceException;
import com.krooj.oauth.common.service.OAuthService;
import com.krooj.oauth.token.domain.AccessTokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

/**
 * Controller to handle requests for tokens
 */
@RestController
public class TokenController {

    private final OAuthService oAuthService;

    @Autowired
    public TokenController(OAuthService oAuthService) {
        this.oAuthService = oAuthService;
    }

    @RequestMapping(value = "/token", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    public AccessTokenResponse exchangeAuthorizationCodeForToken(@RequestParam String code,
                                                                 @RequestParam("redirect_uri") URI redirectUri,
                                                                 @RequestParam("grant_type") GrantType grantType,
                                                                 Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof Client) {
            Client client = (Client) principal;
            return oAuthService.exchangeAuthorizationCodeForToken(code, grantType, client.getClientId(), redirectUri);
        } else {
            throw new OAuthServiceException("error.authentication.unsupported");
        }
    }

}
