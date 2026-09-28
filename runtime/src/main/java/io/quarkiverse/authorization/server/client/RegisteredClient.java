package io.quarkiverse.authorization.server.client;

import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.settings.TokenSettings;

/**
 * A registered OAuth 2.0 client.
 */
public final class RegisteredClient implements Serializable {

    @Serial
    private static final long serialVersionUID = 4111389332052412613L;

    private final String id;
    private final String clientId;
    private final Instant clientIdIssuedAt;
    private final String clientSecret;
    private final Instant clientSecretExpiresAt;
    private final String clientName;
    private final Set<ClientAuthenticationMethod> clientAuthenticationMethods;
    private final Set<AuthorizationGrantType> authorizationGrantTypes;
    private final Set<String> redirectUris;
    private final Set<String> postLogoutRedirectUris;
    private final Set<String> scopes;
    private final ClientSettings clientSettings;
    private final TokenSettings tokenSettings;

    private RegisteredClient(Builder builder) {
        this.id = builder.id;
        this.clientId = builder.clientId;
        this.clientIdIssuedAt = builder.clientIdIssuedAt;
        this.clientSecret = builder.clientSecret;
        this.clientSecretExpiresAt = builder.clientSecretExpiresAt;
        this.clientName = builder.clientName;
        this.clientAuthenticationMethods = immutableCopy(builder.clientAuthenticationMethods);
        this.authorizationGrantTypes = immutableCopy(builder.authorizationGrantTypes);
        this.redirectUris = immutableCopy(builder.redirectUris);
        this.postLogoutRedirectUris = immutableCopy(builder.postLogoutRedirectUris);
        this.scopes = immutableCopy(builder.scopes);
        this.clientSettings = builder.clientSettings;
        this.tokenSettings = builder.tokenSettings;
    }

    public String getId() {
        return this.id;
    }

    public String getClientId() {
        return this.clientId;
    }

    public Instant getClientIdIssuedAt() {
        return this.clientIdIssuedAt;
    }

    public String getClientSecret() {
        return this.clientSecret;
    }

    public Instant getClientSecretExpiresAt() {
        return this.clientSecretExpiresAt;
    }

    public String getClientName() {
        return this.clientName;
    }

    public Set<ClientAuthenticationMethod> getClientAuthenticationMethods() {
        return this.clientAuthenticationMethods;
    }

    public Set<AuthorizationGrantType> getAuthorizationGrantTypes() {
        return this.authorizationGrantTypes;
    }

    public Set<String> getRedirectUris() {
        return this.redirectUris;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public Set<String> getPostLogoutRedirectUris() {
        return this.postLogoutRedirectUris;
    }

    public ClientSettings getClientSettings() {
        return this.clientSettings;
    }

    public TokenSettings getTokenSettings() {
        return this.tokenSettings;
    }

    public static Builder withId(String id) {
        Arguments.requireNonBlank(id, "id");
        return new Builder(id);
    }

    public static Builder from(RegisteredClient registeredClient) {
        Objects.requireNonNull(registeredClient, "registeredClient cannot be null");
        return new Builder(registeredClient);
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof RegisteredClient that)) {
            return false;
        }
        return this.id.equals(that.id)
                && this.clientId.equals(that.clientId)
                && Objects.equals(this.clientIdIssuedAt, that.clientIdIssuedAt)
                && Objects.equals(this.clientSecret, that.clientSecret)
                && Objects.equals(this.clientSecretExpiresAt, that.clientSecretExpiresAt)
                && this.clientName.equals(that.clientName)
                && this.clientAuthenticationMethods.equals(that.clientAuthenticationMethods)
                && this.authorizationGrantTypes.equals(that.authorizationGrantTypes)
                && this.redirectUris.equals(that.redirectUris)
                && this.postLogoutRedirectUris.equals(that.postLogoutRedirectUris)
                && this.scopes.equals(that.scopes)
                && this.clientSettings.equals(that.clientSettings)
                && this.tokenSettings.equals(that.tokenSettings);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.id, this.clientId, this.clientIdIssuedAt, this.clientSecret,
                this.clientSecretExpiresAt, this.clientName, this.clientAuthenticationMethods,
                this.authorizationGrantTypes, this.redirectUris, this.postLogoutRedirectUris, this.scopes, this.clientSettings,
                this.tokenSettings);
    }

    @Override
    public String toString() {
        return "RegisteredClient {id='" + this.id + "', clientId='" + this.clientId + "', clientName='" + this.clientName
                + "', clientAuthenticationMethods=" + this.clientAuthenticationMethods
                + ", authorizationGrantTypes=" + this.authorizationGrantTypes + ", redirectUris=" + this.redirectUris
                + ", postLogoutRedirectUris=" + this.postLogoutRedirectUris
                + ", scopes=" + this.scopes + ", clientSettings=" + this.clientSettings
                + ", tokenSettings=" + this.tokenSettings + "}";
    }

    private static <T> Set<T> immutableCopy(Set<T> values) {
        return Collections.unmodifiableSet(new LinkedHashSet<>(values));
    }

    public static final class Builder implements Serializable {

        @Serial
        private static final long serialVersionUID = -8787809103182161420L;

        private String id;
        private String clientId;
        private Instant clientIdIssuedAt;
        private String clientSecret;
        private Instant clientSecretExpiresAt;
        private String clientName;
        private final Set<ClientAuthenticationMethod> clientAuthenticationMethods = new LinkedHashSet<>();
        private final Set<AuthorizationGrantType> authorizationGrantTypes = new LinkedHashSet<>();
        private final Set<String> redirectUris = new LinkedHashSet<>();
        private final Set<String> postLogoutRedirectUris = new LinkedHashSet<>();
        private final Set<String> scopes = new LinkedHashSet<>();
        private ClientSettings clientSettings;
        private TokenSettings tokenSettings;

        private Builder(String id) {
            this.id = id;
        }

        private Builder(RegisteredClient registeredClient) {
            this.id = registeredClient.getId();
            this.clientId = registeredClient.getClientId();
            this.clientIdIssuedAt = registeredClient.getClientIdIssuedAt();
            this.clientSecret = registeredClient.getClientSecret();
            this.clientSecretExpiresAt = registeredClient.getClientSecretExpiresAt();
            this.clientName = registeredClient.getClientName();
            this.clientAuthenticationMethods.addAll(registeredClient.getClientAuthenticationMethods());
            this.authorizationGrantTypes.addAll(registeredClient.getAuthorizationGrantTypes());
            this.redirectUris.addAll(registeredClient.getRedirectUris());
            this.postLogoutRedirectUris.addAll(registeredClient.getPostLogoutRedirectUris());
            this.scopes.addAll(registeredClient.getScopes());
            this.clientSettings = ClientSettings.withSettings(
                    registeredClient.getClientSettings().getSettings()).build();
            this.tokenSettings = registeredClient.getTokenSettings();
        }

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder clientIdIssuedAt(Instant clientIdIssuedAt) {
            this.clientIdIssuedAt = clientIdIssuedAt;
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder clientSecretExpiresAt(Instant clientSecretExpiresAt) {
            this.clientSecretExpiresAt = clientSecretExpiresAt;
            return this;
        }

        public Builder clientName(String clientName) {
            this.clientName = clientName;
            return this;
        }

        public Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
            this.clientAuthenticationMethods.add(Objects.requireNonNull(clientAuthenticationMethod));
            return this;
        }

        public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
            this.authorizationGrantTypes.add(Objects.requireNonNull(authorizationGrantType));
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            Arguments.requireNonBlank(redirectUri, "redirectUri");
            this.redirectUris.add(redirectUri);
            return this;
        }

        public Builder scope(String scope) {
            Arguments.requireNonBlank(scope, "scope");
            this.scopes.add(scope);
            return this;
        }

        public Builder postLogoutRedirectUri(String postLogoutRedirectUri) {
            Arguments.requireNonBlank(postLogoutRedirectUri, "postLogoutRedirectUri");
            this.postLogoutRedirectUris.add(postLogoutRedirectUri);
            return this;
        }

        public Builder postLogoutRedirectUris(Consumer<Set<String>> postLogoutRedirectUrisConsumer) {
            postLogoutRedirectUrisConsumer.accept(this.postLogoutRedirectUris);
            return this;
        }

        public Builder clientSettings(ClientSettings clientSettings) {
            this.clientSettings = Objects.requireNonNull(clientSettings, "clientSettings cannot be null");
            return this;
        }

        public Builder tokenSettings(TokenSettings tokenSettings) {
            this.tokenSettings = Objects.requireNonNull(tokenSettings, "tokenSettings cannot be null");
            return this;
        }

        public RegisteredClient build() {
            Arguments.requireNonBlank(this.id, "id");
            Arguments.requireNonBlank(this.clientId, "clientId");
            if (this.clientName == null || this.clientName.isBlank()) {
                this.clientName = this.id;
            }
            if (this.clientAuthenticationMethods.isEmpty()) {
                this.clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            }
            if (this.authorizationGrantTypes.isEmpty()) {
                throw new IllegalArgumentException("authorizationGrantTypes cannot be empty");
            }
            if (this.authorizationGrantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)
                    && this.redirectUris.isEmpty()) {
                throw new IllegalArgumentException("redirectUris cannot be empty");
            }
            if (this.clientSettings == null) {
                ClientSettings.Builder builder = ClientSettings.builder();
                if (isPublicClientType()) {
                    builder.requireProofKey(true).requireAuthorizationConsent(true);
                }
                this.clientSettings = builder.build();
            }
            if (this.tokenSettings == null) {
                this.tokenSettings = TokenSettings.builder().build();
            }
            validateScopes();
            validateRedirectUris();
            for (String uri : this.postLogoutRedirectUris) {
                if (uri == null || !validateRedirectUri(uri)) {
                    throw new IllegalArgumentException("post_logout_redirect_uri is invalid or contains a fragment");
                }
            }
            return new RegisteredClient(this);
        }

        private boolean isPublicClientType() {
            return this.authorizationGrantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)
                    && this.clientAuthenticationMethods.size() == 1
                    && this.clientAuthenticationMethods.contains(ClientAuthenticationMethod.NONE);
        }

        private void validateScopes() {
            for (String scope : this.scopes) {
                if (!validateScope(scope)) {
                    throw new IllegalArgumentException("scope \"" + scope + "\" contains invalid characters");
                }
            }
        }

        private static boolean validateScope(String scope) {
            return scope == null
                    || scope.chars().allMatch(character -> withinTheRangeOf(character, 0x21, 0x21)
                            || withinTheRangeOf(character, 0x23, 0x5B)
                            || withinTheRangeOf(character, 0x5D, 0x7E));
        }

        private static boolean withinTheRangeOf(int character, int minimum, int maximum) {
            return character >= minimum && character <= maximum;
        }

        private void validateRedirectUris() {
            for (String redirectUri : this.redirectUris) {
                if (!validateRedirectUri(redirectUri)) {
                    throw new IllegalArgumentException(
                            "redirect_uri \"" + redirectUri + "\" is not a valid redirect URI or contains fragment");
                }
            }
        }

        private static boolean validateRedirectUri(String redirectUri) {
            try {
                URI validRedirectUri = new URI(redirectUri);
                return validRedirectUri.getFragment() == null;
            } catch (URISyntaxException exception) {
                return false;
            }
        }
    }
}
