package io.quarkiverse.authorization.server.oidc;

import io.quarkiverse.authorization.server.metadata.OAuth2AuthorizationServerMetadataClaimNames;

/**
 * OpenID Provider metadata claim names extending the OAuth 2.0 authorization server metadata.
 */
public final class OidcProviderMetadataClaimNames extends OAuth2AuthorizationServerMetadataClaimNames {

    public static final String SUBJECT_TYPES_SUPPORTED = "subject_types_supported";
    public static final String ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED = "id_token_signing_alg_values_supported";
    public static final String USER_INFO_ENDPOINT = "userinfo_endpoint";
    public static final String END_SESSION_ENDPOINT = "end_session_endpoint";

    private OidcProviderMetadataClaimNames() {
    }
}
