package io.quarkiverse.authorization.server.model;

/**
 * Standard OAuth 2.0 error codes.
 */
public final class OAuth2ErrorCodes {
    public static final String INVALID_TOKEN = "invalid_token";
    public static final String INSUFFICIENT_SCOPE = "insufficient_scope";

    public static final String ACCESS_DENIED = "access_denied";
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String INVALID_GRANT = "invalid_grant";
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_SCOPE = "invalid_scope";
    public static final String INVALID_DPOP_PROOF = "invalid_dpop_proof";

    public static final String SERVER_ERROR = "server_error";
    public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
    public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    public static final String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    public static final String UNSUPPORTED_TOKEN_TYPE = "unsupported_token_type";

    private OAuth2ErrorCodes() {
    }
}
