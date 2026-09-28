package io.quarkiverse.authorization.server.token;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Default implementation of {@link OAuth2TokenContext}.
 */
public final class DefaultOAuth2TokenContext implements OAuth2TokenContext {

    private final Map<Object, Object> context;

    private DefaultOAuth2TokenContext(Map<Object, Object> context) {
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

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractBuilder<DefaultOAuth2TokenContext, Builder> {

        private Builder() {
        }

        @Override
        public DefaultOAuth2TokenContext build() {
            return new DefaultOAuth2TokenContext(getContext());
        }
    }
}
