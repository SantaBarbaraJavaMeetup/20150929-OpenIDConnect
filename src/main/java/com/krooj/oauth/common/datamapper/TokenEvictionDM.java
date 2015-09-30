package com.krooj.oauth.common.datamapper;

/**
 *
 */
public interface TokenEvictionDM {

    void markTokenAsConsumed(String token);

    boolean isTokenConsumed(String token);

}
