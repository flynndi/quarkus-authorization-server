package io.quarkiverse.authorization.server.runtime.oidc.registration;

import java.util.List;

import jakarta.enterprise.inject.Default;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.registration.RegistrationClientSettingsCustomizer;
import io.quarkiverse.authorization.server.client.registration.RegistrationTokenSettingsCustomizer;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.oidc.registration.RegisteredClientMapper;
import io.quarkiverse.authorization.server.runtime.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkus.arc.All;
import io.quarkus.arc.DefaultBean;

/** Combines supported algorithms with CDI registration settings customizers. */
@Singleton
@DefaultBean
public final class DefaultRegisteredClientMapper implements RegisteredClientMapper {
    private final java.util.function.Function<OidcClientRegistration, RegisteredClient> converter;

    @Inject
    public DefaultRegisteredClientMapper(
            AuthorizationServerKeyManager keys,
            @All @Default List<RegistrationClientSettingsCustomizer> clientSettings,
            @All @Default List<RegistrationTokenSettingsCustomizer> tokenSettings) {
        var clientCustomizers = List.copyOf(clientSettings);
        var tokenCustomizers = List.copyOf(tokenSettings);
        // Capture CDI references here; invoke customizers only when mapping a request so
        // request-scoped dependencies remain in the protocol execution context.
        this.converter = registration -> new OidcClientRegistrationRegisteredClientConverter(
                keys.getSigningAlgorithms(),
                settings -> clientCustomizers.forEach(
                        customizer -> customizer.customize(settings)),
                settings -> tokenCustomizers.forEach(
                        customizer -> customizer.customize(settings)))
                .convert(registration);
    }

    @Override
    public RegisteredClient map(OidcClientRegistration registration) {
        return this.converter.apply(registration);
    }
}
