package io.quarkiverse.authorization.server.metadata;

import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Base representation of OAuth 2.0 Authorization Server Metadata.
 */
public abstract class AbstractOAuth2AuthorizationServerMetadata
        implements OAuth2AuthorizationServerMetadataClaimAccessor, Serializable {

    @Serial
    private static final long serialVersionUID = 8098320660379633483L;

    private final Map<String, Object> claims;

    protected AbstractOAuth2AuthorizationServerMetadata(Map<String, Object> claims) {
        if (claims == null || claims.isEmpty()) {
            throw new IllegalArgumentException("claims cannot be empty");
        }
        this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    @Override
    public Map<String, Object> getClaims() {
        return this.claims;
    }

    /**
     * Base builder shared by OAuth 2.0 and OpenID Provider metadata.
     */
    protected abstract static class AbstractBuilder<T extends AbstractOAuth2AuthorizationServerMetadata, B extends AbstractBuilder<T, B>> {

        private final Map<String, Object> claims = new LinkedHashMap<>();

        protected Map<String, Object> getClaims() {
            return this.claims;
        }

        @SuppressWarnings("unchecked")
        protected final B getThis() {
            return (B) this;
        }

        public B issuer(String issuer) {
            return claim(OAuth2AuthorizationServerMetadataClaimNames.ISSUER, issuer);
        }

        public B authorizationEndpoint(String authorizationEndpoint) {
            return claim(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT,
                    authorizationEndpoint);
        }

        public B deviceAuthorizationEndpoint(String deviceAuthorizationEndpoint) {
            return claim(OAuth2AuthorizationServerMetadataClaimNames.DEVICE_AUTHORIZATION_ENDPOINT,
                    deviceAuthorizationEndpoint);
        }

        public B tokenEndpoint(String tokenEndpoint) {
            return claim(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, tokenEndpoint);
        }

        public B tokenEndpointAuthenticationMethod(String authenticationMethod) {
            addClaimToClaimList(
                    OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
                    authenticationMethod);
            return getThis();
        }

        public B tokenEndpointAuthenticationMethods(
                Consumer<List<String>> authenticationMethodsConsumer) {
            acceptClaimValues(
                    OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
                    authenticationMethodsConsumer);
            return getThis();
        }

        public B tokenEndpointAuthenticationSigningAlgorithms(Consumer<List<String>> consumer) {
            acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED,
                    consumer);
            return getThis();
        }

        public B tokenIntrospectionEndpointAuthenticationSigningAlgorithms(Consumer<List<String>> consumer) {
            acceptClaimValues(
                    OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED,
                    consumer);
            return getThis();
        }

        public B tokenRevocationEndpointAuthenticationSigningAlgorithms(Consumer<List<String>> consumer) {
            acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED,
                    consumer);
            return getThis();
        }

        public B jwkSetUrl(String jwkSetUrl) {
            return claim(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI, jwkSetUrl);
        }

        public B scope(String scope) {
            addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED, scope);
            return getThis();
        }

        public B scopes(Consumer<List<String>> scopesConsumer) {
            acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED, scopesConsumer);
            return getThis();
        }

        public B responseType(String responseType) {
            addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED,
                    responseType);
            return getThis();
        }

        public B responseTypes(Consumer<List<String>> responseTypesConsumer) {
            acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED,
                    responseTypesConsumer);
            return getThis();
        }

        public B grantType(String grantType) {
            addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED, grantType);
            return getThis();
        }

        public B grantTypes(Consumer<List<String>> grantTypesConsumer) {
            acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED,
                    grantTypesConsumer);
            return getThis();
        }

        public B tokenRevocationEndpoint(String tokenRevocationEndpoint) {
            return claim(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT,
                    tokenRevocationEndpoint);
        }

        public B tokenRevocationEndpointAuthenticationMethod(String authenticationMethod) {
            addClaimToClaimList(
                    OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED,
                    authenticationMethod);
            return getThis();
        }

        public B tokenRevocationEndpointAuthenticationMethods(
                Consumer<List<String>> authenticationMethodsConsumer) {
            acceptClaimValues(
                    OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED,
                    authenticationMethodsConsumer);
            return getThis();
        }

        public B tokenIntrospectionEndpoint(String tokenIntrospectionEndpoint) {
            return claim(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT,
                    tokenIntrospectionEndpoint);
        }

        public B tokenIntrospectionEndpointAuthenticationMethod(String authenticationMethod) {
            addClaimToClaimList(
                    OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED,
                    authenticationMethod);
            return getThis();
        }

        public B tokenIntrospectionEndpointAuthenticationMethods(
                Consumer<List<String>> authenticationMethodsConsumer) {
            acceptClaimValues(
                    OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED,
                    authenticationMethodsConsumer);
            return getThis();
        }

        public B clientRegistrationEndpoint(String clientRegistrationEndpoint) {
            return claim(OAuth2AuthorizationServerMetadataClaimNames.REGISTRATION_ENDPOINT,
                    clientRegistrationEndpoint);
        }

        public B codeChallengeMethod(String codeChallengeMethod) {
            addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED,
                    codeChallengeMethod);
            return getThis();
        }

        public B codeChallengeMethods(Consumer<List<String>> codeChallengeMethodsConsumer) {
            acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED,
                    codeChallengeMethodsConsumer);
            return getThis();
        }

        public B dPoPSigningAlgorithm(String algorithm) {
            addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED,
                    algorithm);
            return getThis();
        }

        public B dPoPSigningAlgorithms(Consumer<List<String>> algorithmsConsumer) {
            acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED,
                    algorithmsConsumer);
            return getThis();
        }

        public B claim(String name, Object value) {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("name cannot be empty");
            }
            this.claims.put(name, Objects.requireNonNull(value, "value cannot be null"));
            return getThis();
        }

        public B claims(Consumer<Map<String, Object>> claimsConsumer) {
            Objects.requireNonNull(claimsConsumer, "claimsConsumer cannot be null").accept(this.claims);
            return getThis();
        }

        public abstract T build();

        protected void validate() {
            requireClaim(OAuth2AuthorizationServerMetadataClaimNames.ISSUER, "issuer cannot be null");
            validateUrlClaim(OAuth2AuthorizationServerMetadataClaimNames.ISSUER,
                    "issuer must be a valid URL");
            requireClaim(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT,
                    "authorizationEndpoint cannot be null");
            validateUrlClaim(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT,
                    "authorizationEndpoint must be a valid URL");
            validateOptionalUrlClaim(OAuth2AuthorizationServerMetadataClaimNames.DEVICE_AUTHORIZATION_ENDPOINT,
                    "deviceAuthorizationEndpoint must be a valid URL");
            requireClaim(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT,
                    "tokenEndpoint cannot be null");
            validateUrlClaim(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT,
                    "tokenEndpoint must be a valid URL");
            validateOptionalListClaim(
                    OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
                    "tokenEndpointAuthenticationMethods");
            validateOptionalListClaim(
                    OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED,
                    "tokenEndpointAuthenticationSigningAlgorithms");
            validateOptionalListClaim(
                    OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED,
                    "tokenIntrospectionEndpointAuthenticationSigningAlgorithms");
            validateOptionalListClaim(
                    OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED,
                    "tokenRevocationEndpointAuthenticationSigningAlgorithms");
            validateOptionalUrlClaim(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI,
                    "jwksUri must be a valid URL");
            validateOptionalListClaim(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED,
                    "scopes");
            requireClaim(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED,
                    "responseTypes cannot be null");
            validateListClaim(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED,
                    "responseTypes");
            validateOptionalListClaim(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED,
                    "grantTypes");
            validateOptionalUrlClaim(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT,
                    "tokenRevocationEndpoint must be a valid URL");
            validateOptionalListClaim(
                    OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED,
                    "tokenRevocationEndpointAuthenticationMethods");
            validateOptionalUrlClaim(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT,
                    "tokenIntrospectionEndpoint must be a valid URL");
            validateOptionalListClaim(
                    OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED,
                    "tokenIntrospectionEndpointAuthenticationMethods");
            validateOptionalUrlClaim(OAuth2AuthorizationServerMetadataClaimNames.REGISTRATION_ENDPOINT,
                    "clientRegistrationEndpoint must be a valid URL");
            validateOptionalListClaim(
                    OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED,
                    "codeChallengeMethods");
            validateOptionalListClaim(
                    OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED,
                    "dPoPSigningAlgorithms");
        }

        @SuppressWarnings("unchecked")
        protected final void addClaimToClaimList(String name, String value) {
            Objects.requireNonNull(value, "value cannot be null");
            this.claims.computeIfAbsent(name, ignored -> new LinkedList<String>());
            ((List<String>) this.claims.get(name)).add(value);
        }

        @SuppressWarnings("unchecked")
        protected final void acceptClaimValues(String name, Consumer<List<String>> valuesConsumer) {
            Objects.requireNonNull(valuesConsumer, "valuesConsumer cannot be null");
            this.claims.computeIfAbsent(name, ignored -> new LinkedList<String>());
            valuesConsumer.accept((List<String>) this.claims.get(name));
        }

        protected final void requireClaim(String claimName, String errorMessage) {
            if (this.claims.get(claimName) == null) {
                throw new IllegalArgumentException(errorMessage);
            }
        }

        protected final void validateOptionalUrlClaim(String claimName, String errorMessage) {
            if (this.claims.get(claimName) != null) {
                validateUrlClaim(claimName, errorMessage);
            }
        }

        private void validateUrlClaim(String claimName, String errorMessage) {
            Object value = this.claims.get(claimName);
            if (value instanceof URL) {
                return;
            }
            try {
                new URI(value.toString()).toURL();
            } catch (Exception exception) {
                throw new IllegalArgumentException(errorMessage, exception);
            }
        }

        private void validateOptionalListClaim(String claimName, String displayName) {
            if (this.claims.get(claimName) != null) {
                validateListClaim(claimName, displayName);
            }
        }

        protected final void validateListClaim(String claimName, String displayName) {
            Object value = this.claims.get(claimName);
            if (!(value instanceof List<?> values)) {
                throw new IllegalArgumentException(displayName + " must be of type List");
            }
            if (values.isEmpty()) {
                throw new IllegalArgumentException(displayName + " cannot be empty");
            }
        }
    }
}
