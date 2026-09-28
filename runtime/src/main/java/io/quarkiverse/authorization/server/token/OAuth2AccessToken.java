package io.quarkiverse.authorization.server.token;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * An OAuth 2.0 Access Token.
 */
public class OAuth2AccessToken extends AbstractOAuth2Token {

    @Serial
    private static final long serialVersionUID = -1954401318439602776L;

    private final TokenType tokenType;
    private final Set<String> scopes;

    public OAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt) {
        this(tokenType, tokenValue, issuedAt, expiresAt, Set.of());
    }

    public OAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt,
            Set<String> scopes) {
        super(tokenValue, issuedAt, expiresAt);
        this.tokenType = Objects.requireNonNull(tokenType, "tokenType cannot be null");
        this.scopes = Collections.unmodifiableSet(new LinkedHashSet<>(scopes != null ? scopes : Set.of()));
    }

    public TokenType getTokenType() {
        return this.tokenType;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public static final class TokenType implements Serializable {

        @Serial
        private static final long serialVersionUID = -7507864842488229809L;

        public static final TokenType BEARER = new TokenType("Bearer");

        public static final TokenType DPOP = new TokenType("DPoP");

        private final String value;

        public TokenType(String value) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("value cannot be empty");
            }
            this.value = value;
        }

        public String getValue() {
            return this.value;
        }

        @Override
        public boolean equals(Object object) {
            return this == object || object instanceof TokenType that && this.value.equals(that.value);
        }

        @Override
        public int hashCode() {
            return this.value.hashCode();
        }
    }
}
