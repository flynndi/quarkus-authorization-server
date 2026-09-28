package io.quarkiverse.authorization.server.oidc;

import java.io.Serial;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import io.quarkiverse.authorization.server.metadata.AbstractOAuth2AuthorizationServerMetadata;

/**
 * An OpenID Provider Configuration Response with a builder for validated metadata claims.
 */
public final class OidcProviderConfiguration extends AbstractOAuth2AuthorizationServerMetadata
        implements OidcProviderMetadataClaimAccessor {

    @Serial
    private static final long serialVersionUID = 2721683488162711072L;

    private OidcProviderConfiguration(Map<String, Object> claims) {
        super(claims);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder withClaims(Map<String, Object> claims) {
        if (claims == null || claims.isEmpty()) {
            throw new IllegalArgumentException("claims cannot be empty");
        }
        return new Builder().claims(values -> values.putAll(claims));
    }

    public static class Builder extends AbstractBuilder<OidcProviderConfiguration, Builder> {

        private Builder() {
        }

        public Builder subjectType(String subjectType) {
            addClaimToClaimList(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, subjectType);
            return this;
        }

        public Builder subjectTypes(Consumer<List<String>> consumer) {
            acceptClaimValues(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, consumer);
            return this;
        }

        public Builder idTokenSigningAlgorithm(String algorithm) {
            addClaimToClaimList(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED, algorithm);
            return this;
        }

        public Builder idTokenSigningAlgorithms(Consumer<List<String>> consumer) {
            acceptClaimValues(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED, consumer);
            return this;
        }

        public Builder userInfoEndpoint(String endpoint) {
            return claim(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT, endpoint);
        }

        public Builder endSessionEndpoint(String endpoint) {
            return claim(OidcProviderMetadataClaimNames.END_SESSION_ENDPOINT, endpoint);
        }

        @Override
        public OidcProviderConfiguration build() {
            validate();
            return new OidcProviderConfiguration(getClaims());
        }

        @Override
        protected void validate() {
            super.validate();
            requireClaim(OidcProviderMetadataClaimNames.JWKS_URI, "jwksUri cannot be null");
            requireClaim(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, "subjectTypes cannot be null");
            validateListClaim(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, "subjectTypes");
            requireClaim(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED,
                    "idTokenSigningAlgorithms cannot be null");
            validateListClaim(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED,
                    "idTokenSigningAlgorithms");
            validateOptionalUrlClaim(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT,
                    "userInfoEndpoint must be a valid URL");
            validateOptionalUrlClaim(OidcProviderMetadataClaimNames.END_SESSION_ENDPOINT,
                    "endSessionEndpoint must be a valid URL");
        }
    }
}
