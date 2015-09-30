package com.krooj.oauth.authorization.domain;

import com.krooj.oauth.common.domain.GrantType;
import lombok.Getter;
import org.hibernate.validator.constraints.NotBlank;

import javax.validation.constraints.NotNull;
import java.net.URI;

/**
 * Domain object to represent the OAuth authorization request, which is the first leg
 * of the 3-legged code grant flow.
 */
public class AuthorizationRequest {


    @Getter
    @NotNull
    private final GrantType grantType;

    @Getter
    @NotBlank
    private final String clientId;

    @Getter
    @NotNull
    private final URI registeredRedirect;

    @Getter
    private final String state;

    public AuthorizationRequest(GrantType grantType, String clientId, URI registeredRedirect, String state) {
        this.grantType = grantType;
        this.clientId = clientId;
        this.registeredRedirect = registeredRedirect;
        this.state = state;
    }
}
