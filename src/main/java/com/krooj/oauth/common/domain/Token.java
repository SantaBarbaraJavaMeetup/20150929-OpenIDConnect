package com.krooj.oauth.common.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;

import java.util.Date;

/**
 * Abstract super class of a token, which can be modeled as:
 * <p>
 * <ul>
 * <li>Authorization code</li>
 * <li>Access token</li>
 * <li>Refresh token</li>
 * </ul>
 */
public abstract class Token {

    public static final long ONE_DAY_MS = 86400000L;

    public static final long TEN_MIN_MS = 600000L;

    public static final long THIRTY_DAYS_MS = ONE_DAY_MS * 30;

    @Getter
    private final Date issueDate;

    @Getter
    private final Date expirationDate;

    @Getter
    private final TokenType tokenType;

    // The audience is WHO this token is intended for.
    @Getter
    private final String audience;

    @Getter
    private final String principal;

    public Token(TokenType tokenType, String audience, String principal, Date issueDate, Date expirationDate) {
        this.tokenType = tokenType;
        this.audience = audience;
        this.principal = principal;
        this.issueDate = issueDate;
        this.expirationDate = expirationDate;
    }

    public abstract String getTokenValue();

    /**
     * Determines whether the given token is non-expired at the time of method execution
     *
     * @return
     */
    @JsonIgnore
    public boolean isNonExpired() {
        return System.currentTimeMillis() <= expirationDate.getTime();
    }

    public static Date assignExpiration(TokenType tokenType, Date issueDate) {
        Date expirationDate;
        switch (tokenType) {
            case ACCESS_TOKEN:
                expirationDate = new Date(issueDate.getTime() + ONE_DAY_MS); //Token expires in a day from issueDate
                break;
            case OPENID:
            case AUTHORIZATION_CODE:
                expirationDate = new Date(issueDate.getTime() + TEN_MIN_MS); //Token expires in 10min from issueDate
                break;
            case REFRESH_TOKEN:
                expirationDate = new Date(issueDate.getTime() + THIRTY_DAYS_MS); //Token expires in 30 days from issueDate
                break;
            default:
                expirationDate = new Date(issueDate.getTime() + ONE_DAY_MS); //Token expires in a day from issueDate
                break;
        }
        return expirationDate;
    }

}
