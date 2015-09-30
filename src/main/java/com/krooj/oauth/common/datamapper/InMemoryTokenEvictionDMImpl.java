package com.krooj.oauth.common.datamapper;

import com.krooj.oauth.common.util.InputValidationUtils;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by michaelkuredjian on 9/27/15.
 */
@Repository
public class InMemoryTokenEvictionDMImpl implements TokenEvictionDM {

    private final Map<String, Boolean> consumedTokens = new ConcurrentHashMap<>();

    @Override
    public void markTokenAsConsumed(String token) {
        InputValidationUtils.assertHasText(token, "error.token.empty");
        consumedTokens.putIfAbsent(token, Boolean.TRUE);
    }

    @Override
    public boolean isTokenConsumed(String token) {
        InputValidationUtils.assertHasText(token, "error.token.empty");
        return consumedTokens.containsKey(token);
    }
}
