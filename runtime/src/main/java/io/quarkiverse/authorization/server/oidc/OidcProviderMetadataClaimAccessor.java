package io.quarkiverse.authorization.server.oidc;

import java.net.URL;
import java.util.List;

import io.quarkiverse.authorization.server.metadata.OAuth2AuthorizationServerMetadataClaimAccessor;

/**
 * Typed access to the OpenID Provider-specific metadata claims.
 */
public interface OidcProviderMetadataClaimAccessor extends OAuth2AuthorizationServerMetadataClaimAccessor {

    default List<String> getSubjectTypes() {
        return getClaimAsStringList(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED);
    }

    default List<String> getIdTokenSigningAlgorithms() {
        return getClaimAsStringList(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED);
    }

    default URL getUserInfoEndpoint() {
        return getClaimAsURL(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT);
    }

    default URL getEndSessionEndpoint() {
        return getClaimAsURL(OidcProviderMetadataClaimNames.END_SESSION_ENDPOINT);
    }
}
