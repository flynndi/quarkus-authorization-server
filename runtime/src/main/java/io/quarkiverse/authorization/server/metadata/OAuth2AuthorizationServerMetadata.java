package io.quarkiverse.authorization.server.metadata;

import java.io.Serial;

import java.util.Map;

/**
 * OAuth 2.0 Authorization Server Metadata.
 */
public final class OAuth2AuthorizationServerMetadata extends AbstractOAuth2AuthorizationServerMetadata {

    @Serial
    private static final long serialVersionUID = 1216377720695714138L;

    private OAuth2AuthorizationServerMetadata(Map<String, Object> claims) {
        super(claims);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder withClaims(Map<String, Object> claims) {
        if (claims == null || claims.isEmpty()) {
            throw new IllegalArgumentException("claims cannot be empty");
        }
        return new Builder().claims(builderClaims -> builderClaims.putAll(claims));
    }

    /**
     * Helps configure an {@link OAuth2AuthorizationServerMetadata}.
     */
    public static class Builder
            extends AbstractBuilder<OAuth2AuthorizationServerMetadata, Builder> {

        private Builder() {
        }

        @Override
        public OAuth2AuthorizationServerMetadata build() {
            validate();
            return new OAuth2AuthorizationServerMetadata(getClaims());
        }
    }
}
