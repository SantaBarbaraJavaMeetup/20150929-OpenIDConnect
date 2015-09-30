package com.krooj.oauth.common.util;

import com.krooj.oauth.common.exception.OAuthServiceException;
import org.springframework.util.StringUtils;

/**
 * Static helper that is used to perform input validations while keeping the contract
 * of throwing an {@link com.krooj.oauth.common.exception.OAuthServiceException}
 */
public abstract class InputValidationUtils {

    /**
     * Checks the passed string for contents and null-ness, and throws an
     * {@link OAuthServiceException} if either case is true
     *
     * @param target The String to check
     * @param code   The code to return in the {@link OAuthServiceException}
     */
    public static void assertHasText(String target, String code) {
        if (!StringUtils.hasText(target)) {
            throw new OAuthServiceException(code);
        }
    }

    /**
     * Checks the passed object for null-ness, and throws an
     * {@link OAuthServiceException} if the reference is null
     *
     * @param target The Object to check
     * @param code   The code to return in the {@link OAuthServiceException}
     */
    public static void assertNotNull(Object target, String code) {
        if (target == null) {
            throw new OAuthServiceException(code);
        }
    }

}
