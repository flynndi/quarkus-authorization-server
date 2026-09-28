package io.quarkiverse.authorization.server.token;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * An {@link OAuth2TokenContext} used when encoding a JWT.
 */
public final class JwtEncodingContext implements OAuth2TokenContext {

    private final Map<Object, Object> context;

    private JwtEncodingContext(Map<Object, Object> context) {
        this.context = Collections.unmodifiableMap(new HashMap<>(context));
    }

    @SuppressWarnings("unchecked")
    @Override
    public <V> V get(Object key) {
        return hasKey(key) ? (V) this.context.get(key) : null;
    }

    @Override
    public boolean hasKey(Object key) {
        return this.context.containsKey(Objects.requireNonNull(key, "key cannot be null"));
    }

    public JwsHeader.Builder getJwsHeader() {
        return get(JwsHeader.Builder.class);
    }

    public JwtClaimsSet.Builder getClaims() {
        return get(JwtClaimsSet.Builder.class);
    }

    public static Builder with(JwsHeader.Builder jwsHeaderBuilder, JwtClaimsSet.Builder claimsBuilder) {
        return new Builder(jwsHeaderBuilder, claimsBuilder);
    }

    public static final class Builder extends AbstractBuilder<JwtEncodingContext, Builder> {

        private Builder(JwsHeader.Builder jwsHeaderBuilder, JwtClaimsSet.Builder claimsBuilder) {
            put(JwsHeader.Builder.class, Objects.requireNonNull(jwsHeaderBuilder, "jwsHeaderBuilder cannot be null"));
            put(JwtClaimsSet.Builder.class, Objects.requireNonNull(claimsBuilder, "claimsBuilder cannot be null"));
        }

        @Override
        public JwtEncodingContext build() {
            return new JwtEncodingContext(getContext());
        }
    }
}
