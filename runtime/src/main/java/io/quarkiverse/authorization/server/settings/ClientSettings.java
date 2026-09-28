package io.quarkiverse.authorization.server.settings;

import java.io.Serial;
import java.util.Map;

import io.quarkiverse.authorization.server.jose.jws.JwsAlgorithm;

/**
 * Configuration settings for an OAuth 2.0 registered client.
 */
public final class ClientSettings extends AbstractSettings {

    @Serial
    private static final long serialVersionUID = -1312785087570836093L;

    private ClientSettings(Map<String, Object> settings) {
        super(settings);
    }

    /**
     * Returns whether the client must provide a proof key challenge and verifier for Authorization Code.
     */
    public boolean isRequireProofKey() {
        return getSetting(ConfigurationSettingNames.Client.REQUIRE_PROOF_KEY);
    }

    /**
     * Returns whether authorization consent is required.
     */
    public boolean isRequireAuthorizationConsent() {
        return getSetting(ConfigurationSettingNames.Client.REQUIRE_AUTHORIZATION_CONSENT);
    }

    public String getJwkSetUrl() {
        return getSetting(ConfigurationSettingNames.Client.JWK_SET_URL);
    }

    public JwsAlgorithm getTokenEndpointAuthenticationSigningAlgorithm() {
        return getSetting(ConfigurationSettingNames.Client.TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM);
    }

    public String getX509CertificateSubjectDN() {
        return getSetting(ConfigurationSettingNames.Client.X509_CERTIFICATE_SUBJECT_DN);
    }

    public static Builder builder() {
        return new Builder()
                .requireProofKey(true)
                .requireAuthorizationConsent(false);
    }

    public static Builder withSettings(Map<String, Object> settings) {
        if (settings == null || settings.isEmpty()) {
            throw new IllegalArgumentException("settings cannot be empty");
        }
        return new Builder().settings(values -> values.putAll(settings));
    }

    public static final class Builder extends AbstractBuilder<ClientSettings, Builder> {

        private Builder() {
        }

        public Builder requireProofKey(boolean requireProofKey) {
            return setting(ConfigurationSettingNames.Client.REQUIRE_PROOF_KEY, requireProofKey);
        }

        public Builder requireAuthorizationConsent(boolean requireAuthorizationConsent) {
            return setting(ConfigurationSettingNames.Client.REQUIRE_AUTHORIZATION_CONSENT,
                    requireAuthorizationConsent);
        }

        public Builder jwkSetUrl(String jwkSetUrl) {
            return setting(ConfigurationSettingNames.Client.JWK_SET_URL, jwkSetUrl);
        }

        public Builder tokenEndpointAuthenticationSigningAlgorithm(JwsAlgorithm authenticationSigningAlgorithm) {
            return setting(ConfigurationSettingNames.Client.TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM,
                    authenticationSigningAlgorithm);
        }

        public Builder x509CertificateSubjectDN(String x509CertificateSubjectDN) {
            return setting(ConfigurationSettingNames.Client.X509_CERTIFICATE_SUBJECT_DN, x509CertificateSubjectDN);
        }

        @Override
        public ClientSettings build() {
            return new ClientSettings(getSettings());
        }
    }
}
