package io.quarkiverse.authorization.server.settings;

/**
 * The names for all authorization server configuration settings.
 */
public final class ConfigurationSettingNames {

    private static final String SETTINGS_NAMESPACE = "settings.";

    private ConfigurationSettingNames() {
    }

    public static final class Client {

        private static final String NAMESPACE = SETTINGS_NAMESPACE + "client.";

        public static final String REQUIRE_PROOF_KEY = NAMESPACE + "require-proof-key";
        public static final String REQUIRE_AUTHORIZATION_CONSENT = NAMESPACE + "require-authorization-consent";
        public static final String JWK_SET_URL = NAMESPACE + "jwk-set-url";
        public static final String TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM = NAMESPACE
                + "token-endpoint-authentication-signing-algorithm";
        public static final String X509_CERTIFICATE_SUBJECT_DN = NAMESPACE + "x509-certificate-subject-dn";

        private Client() {
        }
    }

    public static final class AuthorizationServer {

        public static final String PUSHED_AUTHORIZATION_REQUEST_ENDPOINT = "settings.authorization-server.pushed-authorization-request-endpoint";

        private static final String NAMESPACE = SETTINGS_NAMESPACE + "authorization-server.";

        public static final String MULTIPLE_ISSUERS_ALLOWED = "settings.authorization-server.multiple-issuers-allowed";

        public static final String ISSUER = NAMESPACE + "issuer";
        public static final String AUTHORIZATION_ENDPOINT = NAMESPACE + "authorization-endpoint";
        public static final String DEVICE_AUTHORIZATION_ENDPOINT = NAMESPACE + "device-authorization-endpoint";
        public static final String DEVICE_VERIFICATION_ENDPOINT = NAMESPACE + "device-verification-endpoint";
        public static final String TOKEN_ENDPOINT = NAMESPACE + "token-endpoint";
        public static final String JWK_SET_ENDPOINT = NAMESPACE + "jwk-set-endpoint";
        public static final String TOKEN_REVOCATION_ENDPOINT = NAMESPACE + "token-revocation-endpoint";
        public static final String TOKEN_INTROSPECTION_ENDPOINT = NAMESPACE + "token-introspection-endpoint";
        public static final String CLIENT_REGISTRATION_ENDPOINT = NAMESPACE + "client-registration-endpoint";
        public static final String OIDC_CLIENT_REGISTRATION_ENDPOINT = NAMESPACE + "oidc-client-registration-endpoint";
        public static final String OIDC_USER_INFO_ENDPOINT = NAMESPACE + "oidc-user-info-endpoint";
        public static final String OIDC_LOGOUT_ENDPOINT = NAMESPACE + "oidc-logout-endpoint";

        private AuthorizationServer() {
        }
    }

    public static final class Token {

        private static final String NAMESPACE = SETTINGS_NAMESPACE + "token.";

        public static final String AUTHORIZATION_CODE_TIME_TO_LIVE = NAMESPACE + "authorization-code-time-to-live";
        public static final String ACCESS_TOKEN_TIME_TO_LIVE = NAMESPACE + "access-token-time-to-live";
        public static final String ACCESS_TOKEN_FORMAT = NAMESPACE + "access-token-format";
        public static final String DEVICE_CODE_TIME_TO_LIVE = NAMESPACE + "device-code-time-to-live";
        public static final String REUSE_REFRESH_TOKENS = NAMESPACE + "reuse-refresh-tokens";
        public static final String REFRESH_TOKEN_TIME_TO_LIVE = NAMESPACE + "refresh-token-time-to-live";
        public static final String ID_TOKEN_SIGNATURE_ALGORITHM = NAMESPACE + "id-token-signature-algorithm";

        private Token() {
        }
    }
}
