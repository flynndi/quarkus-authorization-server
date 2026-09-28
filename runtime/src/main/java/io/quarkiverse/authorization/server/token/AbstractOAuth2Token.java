package io.quarkiverse.authorization.server.token;

import java.io.Serial;
import java.time.Instant;
import java.util.Objects;

/**
 * Base implementation of an OAuth 2.0 Token.
 */
public abstract class AbstractOAuth2Token implements OAuth2Token {

    @Serial
    private static final long serialVersionUID = -5957000348330585943L;

    private final String tokenValue;
    private final Instant issuedAt;
    private final Instant expiresAt;

    protected AbstractOAuth2Token(String tokenValue, Instant issuedAt, Instant expiresAt) {
        if (tokenValue == null || tokenValue.isBlank()) {
            throw new IllegalArgumentException("tokenValue cannot be empty");
        }
        if (issuedAt != null && expiresAt != null && !expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("expiresAt must be after issuedAt");
        }
        this.tokenValue = tokenValue;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    @Override
    public String getTokenValue() {
        return this.tokenValue;
    }

    @Override
    public Instant getIssuedAt() {
        return this.issuedAt;
    }

    @Override
    public Instant getExpiresAt() {
        return this.expiresAt;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        AbstractOAuth2Token that = (AbstractOAuth2Token) object;
        return this.tokenValue.equals(that.tokenValue)
                && Objects.equals(this.issuedAt, that.issuedAt)
                && Objects.equals(this.expiresAt, that.expiresAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.tokenValue, this.issuedAt, this.expiresAt);
    }
}
