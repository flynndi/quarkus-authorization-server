package io.quarkiverse.authorization.server.client.registration;

/** RFC 7591 fields supported by the OAuth registration endpoint. */
public final class OAuth2ClientMetadataClaimNames {
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_ID_ISSUED_AT = "client_id_issued_at";
    public static final String CLIENT_NAME = "client_name";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String CLIENT_SECRET_EXPIRES_AT = "client_secret_expires_at";
    public static final String TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";
    public static final String GRANT_TYPES = "grant_types";
    public static final String RESPONSE_TYPES = "response_types";
    public static final String REDIRECT_URIS = "redirect_uris";
    public static final String SCOPE = "scope";

    private OAuth2ClientMetadataClaimNames() {
    }
}
