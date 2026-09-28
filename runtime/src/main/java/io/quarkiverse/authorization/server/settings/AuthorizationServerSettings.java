package io.quarkiverse.authorization.server.settings;

import java.io.Serial;

import java.util.Map;

/**
 * A facility for authorization server configuration settings.
 */
public final class AuthorizationServerSettings extends AbstractSettings {

    @Serial
    private static final long serialVersionUID = 3421728370215641232L;

    private AuthorizationServerSettings(Map<String, Object> settings) {
        super(settings);
    }

    public boolean isMultipleIssuersAllowed() {
        return Boolean.TRUE.equals(this.getSetting(ConfigurationSettingNames.AuthorizationServer.MULTIPLE_ISSUERS_ALLOWED));
    }

    public String getIssuer() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.ISSUER);
    }

    public String getAuthorizationEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.AUTHORIZATION_ENDPOINT);
    }

    /** Null when the optional PAR endpoint is not installed. */
    public String getPushedAuthorizationRequestEndpoint() {
        return this.getSetting(ConfigurationSettingNames.AuthorizationServer.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT);
    }

    public String getDeviceAuthorizationEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.DEVICE_AUTHORIZATION_ENDPOINT);
    }

    public String getDeviceVerificationEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.DEVICE_VERIFICATION_ENDPOINT);
    }

    public String getTokenEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.TOKEN_ENDPOINT);
    }

    public String getJwkSetEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.JWK_SET_ENDPOINT);
    }

    public String getTokenRevocationEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.TOKEN_REVOCATION_ENDPOINT);
    }

    public String getTokenIntrospectionEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.TOKEN_INTROSPECTION_ENDPOINT);
    }

    /** Null when independent OAuth registration is disabled. */
    public String getClientRegistrationEndpoint() {
        return this.getSetting(ConfigurationSettingNames.AuthorizationServer.CLIENT_REGISTRATION_ENDPOINT);
    }

    public String getOidcClientRegistrationEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.OIDC_CLIENT_REGISTRATION_ENDPOINT);
    }

    public String getOidcUserInfoEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.OIDC_USER_INFO_ENDPOINT);
    }

    public String getOidcLogoutEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.OIDC_LOGOUT_ENDPOINT);
    }

    public static Builder builder() {
        return new Builder()
                .authorizationEndpoint("/oauth2/authorize")
                .deviceAuthorizationEndpoint("/oauth2/device_authorization")
                .deviceVerificationEndpoint("/oauth2/device_verification")
                .tokenEndpoint("/oauth2/token")
                .jwkSetEndpoint("/oauth2/jwks")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .oidcClientRegistrationEndpoint("/connect/register")
                .oidcUserInfoEndpoint("/userinfo")
                .oidcLogoutEndpoint("/connect/logout");
    }

    public static Builder withSettings(Map<String, Object> settings) {
        if (settings == null || settings.isEmpty()) {
            throw new IllegalArgumentException("settings cannot be empty");
        }
        return new Builder().settings(values -> values.putAll(settings));
    }

    public static final class Builder extends AbstractBuilder<AuthorizationServerSettings, Builder> {

        private Builder() {
        }

        public Builder multipleIssuersAllowed(boolean allowed) {
            return this.setting(ConfigurationSettingNames.AuthorizationServer.MULTIPLE_ISSUERS_ALLOWED, allowed);
        }

        public Builder issuer(String issuer) {
            return setting(ConfigurationSettingNames.AuthorizationServer.ISSUER, issuer);
        }

        public Builder authorizationEndpoint(String authorizationEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.AUTHORIZATION_ENDPOINT, authorizationEndpoint);
        }

        public Builder pushedAuthorizationRequestEndpoint(String endpoint) {
            return this.setting(ConfigurationSettingNames.AuthorizationServer.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT, endpoint);
        }

        public Builder deviceAuthorizationEndpoint(String deviceAuthorizationEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.DEVICE_AUTHORIZATION_ENDPOINT,
                    deviceAuthorizationEndpoint);
        }

        public Builder deviceVerificationEndpoint(String deviceVerificationEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.DEVICE_VERIFICATION_ENDPOINT,
                    deviceVerificationEndpoint);
        }

        public Builder tokenEndpoint(String tokenEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.TOKEN_ENDPOINT, tokenEndpoint);
        }

        public Builder jwkSetEndpoint(String jwkSetEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.JWK_SET_ENDPOINT, jwkSetEndpoint);
        }

        public Builder tokenRevocationEndpoint(String tokenRevocationEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.TOKEN_REVOCATION_ENDPOINT,
                    tokenRevocationEndpoint);
        }

        public Builder tokenIntrospectionEndpoint(String tokenIntrospectionEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.TOKEN_INTROSPECTION_ENDPOINT,
                    tokenIntrospectionEndpoint);
        }

        public Builder clientRegistrationEndpoint(String endpoint) {
            return this.setting(ConfigurationSettingNames.AuthorizationServer.CLIENT_REGISTRATION_ENDPOINT, endpoint);
        }

        public Builder oidcClientRegistrationEndpoint(String oidcClientRegistrationEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.OIDC_CLIENT_REGISTRATION_ENDPOINT,
                    oidcClientRegistrationEndpoint);
        }

        public Builder oidcUserInfoEndpoint(String oidcUserInfoEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.OIDC_USER_INFO_ENDPOINT, oidcUserInfoEndpoint);
        }

        public Builder oidcLogoutEndpoint(String oidcLogoutEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.OIDC_LOGOUT_ENDPOINT, oidcLogoutEndpoint);
        }

        @Override
        public AuthorizationServerSettings build() {
            return new AuthorizationServerSettings(getSettings());
        }
    }
}
