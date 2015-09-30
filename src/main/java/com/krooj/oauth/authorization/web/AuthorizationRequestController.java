package com.krooj.oauth.authorization.web;

import com.krooj.oauth.common.domain.Scopes;
import com.krooj.oauth.common.exception.OAuthServiceException;
import com.krooj.oauth.common.service.OAuthService;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;

/**
 * Controller that handles creation and retrieval of {@link com.krooj.oauth.authorization.domain.AuthorizationRequest}s
 */
@Controller
@Log4j2
public class AuthorizationRequestController {

    private OAuthService oAuthService;

    @Autowired
    public AuthorizationRequestController(OAuthService oAuthService) {
        this.oAuthService = oAuthService;
    }


    @PreAuthorize("hasRole('ROLE_USER') and isAuthenticated()")
    @RequestMapping(value = "/authorize", method = {RequestMethod.GET}, params = {"grant_type", "client_id"})
    public RedirectView createAuthorizationRequest(@RequestParam("client_id") String clientId,
                                                   @RequestParam("redirect_uri") URI redirectUri,
                                                   @RequestParam(required = false) String state,
                                                   @RequestParam(value = "scope", required = false) String requestedScopes, Authentication authentication) {
        if (authentication.getPrincipal() instanceof User) {
            String principal = ((User) authentication.getPrincipal()).getUsername();
            URI redirect = oAuthService.createAuthorizationRequest(clientId, principal, redirectUri, state,
                    requestedScopes == null ? Collections.emptyList() : Scopes.fromString(requestedScopes));
            return new RedirectView(redirect.toString(), false, false);
        } else {
            throw new OAuthServiceException("error.credentials.type.unsupported");
        }
    }

    @PreAuthorize("hasRole('ROLE_USER') and isAuthenticated()")
    @RequestMapping(value = "/authorize", method = {RequestMethod.GET}, params = {"response_type", "client_id", "redirect_uri"})
    public RedirectView createImplicitAuthorizationRequest(@RequestParam("response_type") String requestedResponseTypes,
                                                           @RequestParam("client_id") String clientId,
                                                           @RequestParam("redirect_uri") URI redirectUri,
                                                           @RequestParam(required = false) String state,
                                                           @RequestParam(required = false) String nonce,
                                                           @RequestParam(value = "scope", required = false) String requestedScopes, Authentication authentication) {
        if (authentication.getPrincipal() instanceof User) {
            String principal = ((User) authentication.getPrincipal()).getUsername();

            URI redirect = oAuthService.createImplicitAuthorization(clientId, principal, redirectUri, state,
                    requestedScopes == null ? Collections.emptyList() : Scopes.fromString(requestedScopes),
                    Arrays.asList(requestedResponseTypes.split(" ")).contains("id_token"), nonce);
            return new RedirectView(redirect.toString(), false, false);
        } else {
            throw new OAuthServiceException("error.credentials.type.unsupported");
        }
    }

}
