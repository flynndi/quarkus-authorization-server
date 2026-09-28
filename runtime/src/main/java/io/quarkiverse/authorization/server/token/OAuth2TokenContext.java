package io.quarkiverse.authorization.server.token;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * A context holding information associated with an OAuth 2.0 Token.
 */
public interface OAuth2TokenContext {

    <V> V get(Object key);

    boolean hasKey(Object key);

    default RegisteredClient getRegisteredClient() {
        return get(RegisteredClient.class);
    }

    /**
     * The token subject's identity, which may have been restored from an authorization record.
     * Restored roles are historical; credentials and live permission checkers are not persisted.
     */
    default SecurityIdentity getPrincipal() {
        return get(AbstractBuilder.PRINCIPAL_KEY);
    }

    default AuthorizationServerContext getAuthorizationServerContext() {
        return get(AuthorizationServerContext.class);
    }

    default OAuth2Authorization getAuthorization() {
        return get(OAuth2Authorization.class);
    }

    default Set<String> getAuthorizedScopes() {
        return hasKey(AbstractBuilder.AUTHORIZED_SCOPE_KEY)
                ? get(AbstractBuilder.AUTHORIZED_SCOPE_KEY)
                : Collections.emptySet();
    }

    default OAuth2TokenType getTokenType() {
        return get(OAuth2TokenType.class);
    }

    default AuthorizationGrantType getAuthorizationGrantType() {
        return get(AuthorizationGrantType.class);
    }

    default <T> T getAuthorizationGrant() {
        return get(AbstractBuilder.AUTHORIZATION_GRANT_KEY);
    }

    abstract class AbstractBuilder<T extends OAuth2TokenContext, B extends AbstractBuilder<T, B>> {

        private static final String PRINCIPAL_KEY = SecurityIdentity.class.getName() + ".PRINCIPAL";
        private static final String AUTHORIZED_SCOPE_KEY = OAuth2TokenContext.class.getName() + ".AUTHORIZED_SCOPE";
        private static final String AUTHORIZATION_GRANT_KEY = OAuth2TokenContext.class.getName() + ".AUTHORIZATION_GRANT";

        private final Map<Object, Object> context = new HashMap<>();

        public B registeredClient(RegisteredClient registeredClient) {
            return put(RegisteredClient.class, registeredClient);
        }

        public B principal(SecurityIdentity principal) {
            return put(PRINCIPAL_KEY, principal);
        }

        public B authorizationServerContext(AuthorizationServerContext authorizationServerContext) {
            return put(AuthorizationServerContext.class, authorizationServerContext);
        }

        public B authorization(OAuth2Authorization authorization) {
            return put(OAuth2Authorization.class, authorization);
        }

        public B authorizedScopes(Set<String> authorizedScopes) {
            return put(AUTHORIZED_SCOPE_KEY, authorizedScopes);
        }

        public B tokenType(OAuth2TokenType tokenType) {
            return put(OAuth2TokenType.class, tokenType);
        }

        public B authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
            return put(AuthorizationGrantType.class, authorizationGrantType);
        }

        public B authorizationGrant(Object authorizationGrant) {
            return put(AUTHORIZATION_GRANT_KEY, authorizationGrant);
        }

        public B put(Object key, Object value) {
            this.context.put(Objects.requireNonNull(key, "key cannot be null"),
                    Objects.requireNonNull(value, "value cannot be null"));
            return getThis();
        }

        public B context(Consumer<Map<Object, Object>> contextConsumer) {
            Objects.requireNonNull(contextConsumer, "contextConsumer cannot be null")
                    .accept(this.context);
            return getThis();
        }

        protected Map<Object, Object> getContext() {
            return this.context;
        }

        @SuppressWarnings("unchecked")
        protected final B getThis() {
            return (B) this;
        }

        public abstract T build();
    }
}
