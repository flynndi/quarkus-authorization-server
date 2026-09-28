package io.quarkiverse.authorization.server.context;

import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;

/**
 * A context that holds authorization server information.
 */
public interface AuthorizationServerContext {

    String getIssuer();

    default boolean isMultipleIssuersAllowed() {
        return this.getAuthorizationServerSettings().isMultipleIssuersAllowed();
    }

    AuthorizationServerSettings getAuthorizationServerSettings();
}
