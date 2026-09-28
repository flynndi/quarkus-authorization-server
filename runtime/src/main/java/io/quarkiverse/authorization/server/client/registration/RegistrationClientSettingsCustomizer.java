package io.quarkiverse.authorization.server.client.registration;

import io.quarkiverse.authorization.server.settings.ClientSettings;

/**
 * Customizes client settings in the default registration mapper, in ArC priority order. This callback
 * runs for each registration and does not change clients supplied by the application repository.
 */
@FunctionalInterface
public interface RegistrationClientSettingsCustomizer {
    void customize(ClientSettings.Builder settings);
}
