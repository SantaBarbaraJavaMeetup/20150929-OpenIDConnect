package com.krooj.oauth.clients.domain;

import com.krooj.oauth.common.domain.GrantType;
import com.krooj.oauth.common.domain.Scopes;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;

import java.net.URI;
import java.util.*;

/**
 * Domain class that represents an OAuth registered client.
 */
public class Client implements UserDetails {

    @Getter
    private final String clientId;

    @Getter
    private final String clientName;

    private final String clientSecret;

    private final Set<URI> registeredRedirects;

    private final Set<GrantType> authorizedGrantTypes;

    private final Set<SimpleGrantedAuthority> clientRoles;

    private final Set<Scopes> eligibleScopes;

    public Client(String clientId, String clientSecret, String clientName, Set<URI> registeredRedirects, Set<GrantType> authorizedGrantTypes, Set<String> clientRoles, Set<Scopes> eligibleScopes) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.clientName = clientName;
        this.registeredRedirects = registeredRedirects;
        this.authorizedGrantTypes = CollectionUtils.isEmpty(authorizedGrantTypes) ? Collections.emptySet() : authorizedGrantTypes;
        this.clientRoles = CollectionUtils.isEmpty(clientRoles) ? Collections.emptySet() : createSimpleRoles(clientRoles);
        this.eligibleScopes = CollectionUtils.isEmpty(eligibleScopes) ? Collections.emptySet() : eligibleScopes;
    }

    private Set<SimpleGrantedAuthority> createSimpleRoles(Set<String> clientRoles) {
        Set<SimpleGrantedAuthority> roles = new HashSet<>();
        for (String role : clientRoles) {
            String roleName = role.startsWith("ROLE_") ? role : "ROLE_" + role;
            roles.add(new SimpleGrantedAuthority(roleName));
        }
        return roles;
    }

    public boolean checkRedirectValidForClient(final URI candidateRedirect) {
        return this.registeredRedirects.contains(candidateRedirect);
    }

    public boolean isGrantAuthorized(GrantType grantType) {
        return authorizedGrantTypes.contains(grantType);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.clientRoles;
    }

    @Override
    public String getPassword() {
        return this.clientSecret;
    }

    @Override
    public String getUsername() {
        return this.clientId;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object obj) {
        boolean result = false;
        if (this.clientId != null) {
            result = this.clientId.equals(obj);
        }
        return result;
    }

    public boolean isEligibleForRequestedScopes(List<Scopes> requestedScopes) {
        return eligibleScopes.containsAll(requestedScopes);
    }
}
