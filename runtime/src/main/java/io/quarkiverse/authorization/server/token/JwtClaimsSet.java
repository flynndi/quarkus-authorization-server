package io.quarkiverse.authorization.server.token;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Claims used when encoding a JWT.
 */
public final class JwtClaimsSet implements ClaimAccessor {

    private final Map<String, Object> claims;

    private JwtClaimsSet(Map<String, Object> claims) {
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

        public Builder issuer(String issuer) {
            return claim("iss", issuer);
        }

        public Builder subject(String subject) {
            return claim("sub", subject);
        }

        public Builder audience(Collection<String> audience) {
            return claim("aud", new ArrayList<>(audience));
        }

        public Builder issuedAt(Instant issuedAt) {
            return claim("iat", issuedAt);
        }

        public Builder expiresAt(Instant expiresAt) {
            return claim("exp", expiresAt);
        }

        public Builder notBefore(Instant notBefore) {
            return claim("nbf", notBefore);
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

        public JwtClaimsSet build() {
            return new JwtClaimsSet(this.claims);
        }
    }
}
