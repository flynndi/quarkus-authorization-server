package io.quarkiverse.authorization.server.client.registration;

import io.quarkiverse.authorization.server.settings.TokenSettings;

/**
 * Customizes token settings in the default registration mapper, in ArC priority order. OIDC and OAuth
 * registration share this callback; it does not modify statically registered clients.
 */
@FunctionalInterface
public interface RegistrationTokenSettingsCustomizer {
    void customize(TokenSettings.Builder settings);
}
