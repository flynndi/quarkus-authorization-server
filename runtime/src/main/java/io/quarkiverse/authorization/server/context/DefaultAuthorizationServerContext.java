package io.quarkiverse.authorization.server.context;

import java.util.Objects;

import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.ConfigurationSettingNames;

/**
 * Default immutable authorization server context.
 */
public final class DefaultAuthorizationServerContext implements AuthorizationServerContext {

    private final AuthorizationServerSettings authorizationServerSettings;

    public DefaultAuthorizationServerContext(AuthorizationServerSettings authorizationServerSettings) {
        this.authorizationServerSettings = Objects.requireNonNull(
                authorizationServerSettings, "authorizationServerSettings cannot be null");
    }

    public DefaultAuthorizationServerContext(AuthorizationServerContext context) {
        this(AuthorizationServerSettings.withSettings(context.getAuthorizationServerSettings().getSettings())
                .settings(values -> {
                    if (context.getIssuer() != null) {
                        values.put(ConfigurationSettingNames.AuthorizationServer.ISSUER, context.getIssuer());
                    }
                }).build());
    }

    @Override
    public String getIssuer() {
        return this.authorizationServerSettings.getIssuer();
    }

    @Override
    public AuthorizationServerSettings getAuthorizationServerSettings() {
        return this.authorizationServerSettings;
    }
}
