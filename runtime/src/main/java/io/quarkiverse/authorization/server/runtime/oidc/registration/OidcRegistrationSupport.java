package io.quarkiverse.authorization.server.runtime.oidc.registration;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;

/**
 * Builds the protected OIDC client-configuration URL.
 */
final class OidcRegistrationSupport {

    private OidcRegistrationSupport() {
    }

    static String registrationClientUrl(AuthorizationServerContext serverContext, String clientId) {
        String issuer = serverContext.getIssuer();
        if (issuer == null || issuer.isBlank()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
        }
        return (issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer)
                + serverContext.getAuthorizationServerSettings().getOidcClientRegistrationEndpoint()
                + "?"
                + OAuth2ParameterNames.CLIENT_ID
                + "="
                + URLEncoder.encode(clientId, StandardCharsets.UTF_8);
    }
}
