package io.quarkiverse.authorization.server.metadata;

/**
 * The names of the claims an Authorization Server describes about its configuration.
 */
public class OAuth2AuthorizationServerMetadataClaimNames {
    public static final String PUSHED_AUTHORIZATION_REQUEST_ENDPOINT = "pushed_authorization_request_endpoint";

    public static final String ISSUER = "issuer";
    public static final String AUTHORIZATION_ENDPOINT = "authorization_endpoint";
    public static final String DEVICE_AUTHORIZATION_ENDPOINT = "device_authorization_endpoint";
    public static final String TOKEN_ENDPOINT = "token_endpoint";
    public static final String TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = "token_endpoint_auth_methods_supported";
    public static final String TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED = "token_endpoint_auth_signing_alg_values_supported";
    public static final String INTROSPECTION_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED = "introspection_endpoint_auth_signing_alg_values_supported";
    public static final String REVOCATION_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED = "revocation_endpoint_auth_signing_alg_values_supported";
    public static final String JWKS_URI = "jwks_uri";
    public static final String SCOPES_SUPPORTED = "scopes_supported";
    public static final String RESPONSE_TYPES_SUPPORTED = "response_types_supported";
    public static final String GRANT_TYPES_SUPPORTED = "grant_types_supported";
    public static final String REVOCATION_ENDPOINT = "revocation_endpoint";
    public static final String REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED = "revocation_endpoint_auth_methods_supported";
    public static final String INTROSPECTION_ENDPOINT = "introspection_endpoint";
    public static final String INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED = "introspection_endpoint_auth_methods_supported";
    public static final String REGISTRATION_ENDPOINT = "registration_endpoint";
    public static final String CODE_CHALLENGE_METHODS_SUPPORTED = "code_challenge_methods_supported";
    public static final String DPOP_SIGNING_ALG_VALUES_SUPPORTED = "dpop_signing_alg_values_supported";

    protected OAuth2AuthorizationServerMetadataClaimNames() {
    }
}
