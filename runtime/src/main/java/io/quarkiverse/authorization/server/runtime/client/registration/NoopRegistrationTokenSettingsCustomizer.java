package io.quarkiverse.authorization.server.runtime.client.registration;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.registration.RegistrationTokenSettingsCustomizer;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkus.arc.DefaultBean;

@Singleton
@DefaultBean
public final class NoopRegistrationTokenSettingsCustomizer
        implements RegistrationTokenSettingsCustomizer {
    @Override
    public void customize(TokenSettings.Builder settings) {
    }
}
