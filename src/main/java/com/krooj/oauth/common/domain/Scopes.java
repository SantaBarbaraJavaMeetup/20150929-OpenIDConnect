package com.krooj.oauth.common.domain;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Scopes that the client can request authorization of from the user or other party.
 * This places limitations on what the resulting token can do.
 */
public enum Scopes {
    openid,
    write;

    public static List<Scopes> fromString(String scopes) {
        if (!StringUtils.hasText(scopes)) {
            return Collections.emptyList();
        }
        List<Scopes> scopeList = new ArrayList<>();
        for (String scope : scopes.split(" ")) {
            scopeList.add(Scopes.valueOf(scope));
        }
        return scopeList;
    }
}
