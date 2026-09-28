package io.quarkiverse.authorization.server.authorization;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;

/**
 * State related to an OAuth 2.0 authorization granted to a registered client. Java serialization
 * requires serializable attributes. JDBC explicitly maps SecurityIdentity, whose Quarkus
 * implementation is not Java-serializable.
 */
public final class OAuth2Authorization implements Serializable {

    @Serial
    private static final long serialVersionUID = -7668751073222914868L;

    private final String id;
    private final String registeredClientId;
    private final String principalName;
    private final AuthorizationGrantType authorizationGrantType;
    private final Set<String> authorizedScopes;
    private final Map<Class<? extends OAuth2Token>, Token<?>> tokens;
    private final Map<String, Object> attributes;

    private OAuth2Authorization(Builder builder) {
        this.id = builder.id;
        this.registeredClientId = builder.registeredClientId;
        this.principalName = builder.principalName;
        this.authorizationGrantType = builder.authorizationGrantType;
        this.authorizedScopes = Collections.unmodifiableSet(new HashSet<>(builder.authorizedScopes));
        this.tokens = Collections.unmodifiableMap(new HashMap<>(builder.tokens));
        this.attributes = Collections.unmodifiableMap(new HashMap<>(builder.attributes));
    }

    public String getId() {
        return this.id;
    }

    public String getRegisteredClientId() {
        return this.registeredClientId;
    }

    public String getPrincipalName() {
        return this.principalName;
    }

    public AuthorizationGrantType getAuthorizationGrantType() {
        return this.authorizationGrantType;
    }

    public Set<String> getAuthorizedScopes() {
        return this.authorizedScopes;
    }

    public Token<OAuth2AccessToken> getAccessToken() {
        return getToken(OAuth2AccessToken.class);
    }

    public Token<OAuth2AuthorizationCode> getAuthorizationCode() {
        return getToken(OAuth2AuthorizationCode.class);
    }

    public Token<OAuth2RefreshToken> getRefreshToken() {
        return getToken(OAuth2RefreshToken.class);
    }

    @SuppressWarnings("unchecked")
    public <T extends OAuth2Token> Token<T> getToken(Class<T> tokenType) {
        Objects.requireNonNull(tokenType, "tokenType cannot be null");
        return (Token<T>) this.tokens.get(tokenType);
    }

    @SuppressWarnings("unchecked")
    public <T extends OAuth2Token> Token<T> getToken(String tokenValue) {
        Arguments.requireNonBlank(tokenValue, "tokenValue");
        for (Token<?> token : this.tokens.values()) {
            if (token.getToken().getTokenValue().equals(tokenValue)) {
                return (Token<T>) token;
            }
        }
        return null;
    }

    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    @SuppressWarnings("unchecked")
    public <T> T getAttribute(String name) {
        Arguments.requireNonBlank(name, "name");
        return (T) this.attributes.get(name);
    }

    public static Builder withRegisteredClient(RegisteredClient registeredClient) {
        Objects.requireNonNull(registeredClient, "registeredClient cannot be null");
        return new Builder(registeredClient.getId());
    }

    public static Builder from(OAuth2Authorization authorization) {
        Objects.requireNonNull(authorization, "authorization cannot be null");
        return new Builder(authorization.getRegisteredClientId())
                .id(authorization.getId())
                .principalName(authorization.getPrincipalName())
                .authorizationGrantType(authorization.getAuthorizationGrantType())
                .authorizedScopes(authorization.getAuthorizedScopes())
                .tokens(authorization.tokens)
                .attributes(attributes -> attributes.putAll(authorization.getAttributes()));
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof OAuth2Authorization that)) {
            return false;
        }
        return Objects.equals(this.id, that.id)
                && Objects.equals(this.registeredClientId, that.registeredClientId)
                && Objects.equals(this.principalName, that.principalName)
                && Objects.equals(this.authorizationGrantType, that.authorizationGrantType)
                && Objects.equals(this.authorizedScopes, that.authorizedScopes)
                && Objects.equals(this.tokens, that.tokens)
                && Objects.equals(this.attributes, that.attributes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.id, this.registeredClientId, this.principalName,
                this.authorizationGrantType, this.authorizedScopes, this.tokens, this.attributes);
    }

    public static final class Token<T extends OAuth2Token> implements Serializable {

        @Serial
        private static final long serialVersionUID = -1129675860191901715L;

        private static final String TOKEN_METADATA_NAMESPACE = "metadata.token.";

        public static final String INVALIDATED_METADATA_NAME = TOKEN_METADATA_NAMESPACE + "invalidated";
        public static final String CLAIMS_METADATA_NAME = TOKEN_METADATA_NAMESPACE + "claims";

        private final T token;
        private final Map<String, Object> metadata;

        private Token(T token, Map<String, Object> metadata) {
            this.token = Objects.requireNonNull(token, "token cannot be null");
            this.metadata = Collections.unmodifiableMap(new HashMap<>(metadata));
        }

        public T getToken() {
            return this.token;
        }

        public boolean isInvalidated() {
            return Boolean.TRUE.equals(getMetadata(INVALIDATED_METADATA_NAME));
        }

        public boolean isExpired() {
            return this.token.getExpiresAt() != null && Instant.now().isAfter(this.token.getExpiresAt());
        }

        public boolean isBeforeUse() {
            Map<String, Object> claims = getClaims();
            Object notBefore = claims != null ? claims.get("nbf") : null;
            return notBefore instanceof Instant instant && Instant.now().isBefore(instant);
        }

        public boolean isActive() {
            return !isInvalidated() && !isExpired() && !isBeforeUse();
        }

        @SuppressWarnings("unchecked")
        public Map<String, Object> getClaims() {
            return (Map<String, Object>) this.metadata.get(CLAIMS_METADATA_NAME);
        }

        @SuppressWarnings("unchecked")
        public <V> V getMetadata(String name) {
            Arguments.requireNonBlank(name, "name");
            return (V) this.metadata.get(name);
        }

        public Map<String, Object> getMetadata() {
            return this.metadata;
        }

        private static Map<String, Object> defaultMetadata() {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put(INVALIDATED_METADATA_NAME, false);
            return metadata;
        }

        @Override
        public boolean equals(Object object) {
            return this == object || object instanceof Token<?> that
                    && this.token.equals(that.token) && this.metadata.equals(that.metadata);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.token, this.metadata);
        }
    }

    public static final class Builder implements Serializable {

        @Serial
        private static final long serialVersionUID = -5265385055550480632L;

        private String id;
        private final String registeredClientId;
        private String principalName;
        private AuthorizationGrantType authorizationGrantType;
        private Set<String> authorizedScopes = Set.of();
        private Map<Class<? extends OAuth2Token>, Token<?>> tokens = new HashMap<>();
        private final Map<String, Object> attributes = new HashMap<>();

        private Builder(String registeredClientId) {
            Arguments.requireNonBlank(registeredClientId, "registeredClientId");
            this.registeredClientId = registeredClientId;
        }

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder principalName(String principalName) {
            this.principalName = principalName;
            return this;
        }

        public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
            this.authorizationGrantType = authorizationGrantType;
            return this;
        }

        public Builder authorizedScopes(Set<String> authorizedScopes) {
            this.authorizedScopes = Objects.requireNonNull(authorizedScopes, "authorizedScopes cannot be null");
            return this;
        }

        public Builder accessToken(OAuth2AccessToken accessToken) {
            return token(accessToken);
        }

        public Builder authorizationCode(OAuth2AuthorizationCode authorizationCode) {
            return token(authorizationCode);
        }

        public Builder refreshToken(OAuth2RefreshToken refreshToken) {
            return token(refreshToken);
        }

        public <T extends OAuth2Token> Builder token(T token) {
            return token(token, metadata -> {
            });
        }

        public <T extends OAuth2Token> Builder token(T token, Consumer<Map<String, Object>> metadataConsumer) {
            Objects.requireNonNull(token, "token cannot be null");
            Objects.requireNonNull(metadataConsumer, "metadataConsumer cannot be null");
            Map<String, Object> metadata = Token.defaultMetadata();
            Token<?> existingToken = this.tokens.get(token.getClass());
            if (existingToken != null) {
                metadata.putAll(existingToken.getMetadata());
            }
            metadataConsumer.accept(metadata);
            this.tokens.put(token.getClass(), new Token<>(token, metadata));
            return this;
        }

        /**
         * Invalidates a token already represented in this builder. Refresh token
         * invalidation also invalidates the associated access token and authorization
         * code when present. Other token types do not cascade.
         */
        public <T extends OAuth2Token> Builder invalidate(T token) {
            Objects.requireNonNull(token, "token cannot be null");
            if (!this.tokens.containsKey(token.getClass())) {
                return this;
            }
            token(token, metadata -> metadata.put(Token.INVALIDATED_METADATA_NAME, true));
            if (token instanceof OAuth2RefreshToken) {
                Token<?> accessToken = this.tokens.get(OAuth2AccessToken.class);
                if (accessToken != null) {
                    token(accessToken.getToken(), metadata -> metadata.put(Token.INVALIDATED_METADATA_NAME, true));
                }
                Token<?> authorizationCode = this.tokens.get(OAuth2AuthorizationCode.class);
                if (authorizationCode != null && !authorizationCode.isInvalidated()) {
                    token(authorizationCode.getToken(), metadata -> metadata.put(Token.INVALIDATED_METADATA_NAME, true));
                }
            }
            return this;
        }

        private Builder tokens(Map<Class<? extends OAuth2Token>, Token<?>> tokens) {
            this.tokens = new HashMap<>(tokens);
            return this;
        }

        public Builder attribute(String name, Object value) {
            Arguments.requireNonBlank(name, "name");
            this.attributes.put(name, Objects.requireNonNull(value, "value cannot be null"));
            return this;
        }

        public Builder attributes(Consumer<Map<String, Object>> attributesConsumer) {
            Objects.requireNonNull(attributesConsumer, "attributesConsumer cannot be null")
                    .accept(this.attributes);
            return this;
        }

        public OAuth2Authorization build() {
            Arguments.requireNonBlank(this.principalName, "principalName");
            Objects.requireNonNull(
                    this.authorizationGrantType, "authorizationGrantType cannot be null");
            if (this.id == null || this.id.isBlank()) {
                this.id = UUID.randomUUID().toString();
            }
            return new OAuth2Authorization(this);
        }
    }
}
