package io.quarkiverse.authorization.server.token;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/** A set of claims associated with an OAuth 2.0 token. */
public final class OAuth2TokenClaimsSet implements ClaimAccessor {
    private final Map<String, Object> claims;

    private OAuth2TokenClaimsSet(Map<String, Object> claims) {
        this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    @Override
    public Map<String, Object> getClaims() {
        return this.claims;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final Map<String, Object> claims = new LinkedHashMap<>();

        private Builder() {
        }

        public Builder issuer(String issuer) {
            return claim("iss", issuer);
        }

        public Builder subject(String subject) {
            return claim("sub", subject);
        }

        public Builder audience(List<String> audience) {
            return claim("aud", audience);
        }

        public Builder expiresAt(Instant expiresAt) {
            return claim("exp", expiresAt);
        }

        public Builder notBefore(Instant notBefore) {
            return claim("nbf", notBefore);
        }

        public Builder issuedAt(Instant issuedAt) {
            return claim("iat", issuedAt);
        }

        public Builder id(String id) {
            return claim("jti", id);
        }

        public Builder claim(String name, Object value) {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("name cannot be empty");
            }
            this.claims.put(name, Objects.requireNonNull(value, "value cannot be null"));
            return this;
        }

        public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
            Objects.requireNonNull(claimsConsumer, "claimsConsumer cannot be null").accept(this.claims);
            return this;
        }

        public OAuth2TokenClaimsSet build() {
            if (this.claims.isEmpty()) {
                throw new IllegalArgumentException("claims cannot be empty");
            }
            return new OAuth2TokenClaimsSet(this.claims);
        }
    }
}
