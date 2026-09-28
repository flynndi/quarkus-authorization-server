package io.quarkiverse.authorization.server.token;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/** Token context exposing mutable claims during opaque access-token customization. */
public final class OAuth2TokenClaimsContext implements OAuth2TokenContext {
    private final Map<Object, Object> context;

    private OAuth2TokenClaimsContext(Map<Object, Object> context) {
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

    public OAuth2TokenClaimsSet.Builder getClaims() {
        return get(OAuth2TokenClaimsSet.Builder.class);
    }

    public static Builder with(OAuth2TokenClaimsSet.Builder claimsBuilder) {
        return new Builder(claimsBuilder);
    }

    public static final class Builder extends AbstractBuilder<OAuth2TokenClaimsContext, Builder> {
        private Builder(OAuth2TokenClaimsSet.Builder claimsBuilder) {
            put(OAuth2TokenClaimsSet.Builder.class,
                    Objects.requireNonNull(claimsBuilder, "claimsBuilder cannot be null"));
        }

        @Override
        public OAuth2TokenClaimsContext build() {
            return new OAuth2TokenClaimsContext(getContext());
        }
    }
}
