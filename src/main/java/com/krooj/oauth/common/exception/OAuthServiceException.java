package com.krooj.oauth.common.exception;

import org.springframework.core.NestedRuntimeException;

/**
 * Exception to be thrown by the service-layer. This will trigger any transactions
 * in the running context to be rolled-back.
 */
public class OAuthServiceException extends NestedRuntimeException {

    public OAuthServiceException(String msg) {
        super(msg);
    }

    public OAuthServiceException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
