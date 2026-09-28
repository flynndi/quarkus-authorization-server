package io.quarkiverse.authorization.server.runtime.client.registration;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.registration.RegistrationClientSettingsCustomizer;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkus.arc.DefaultBean;

@Singleton
@DefaultBean
public final class NoopRegistrationClientSettingsCustomizer
        implements RegistrationClientSettingsCustomizer {
    @Override
    public void customize(ClientSettings.Builder settings) {
    }
}
