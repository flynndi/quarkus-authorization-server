package io.quarkiverse.authorization.server.runtime.client.web;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.web.authentication.AuthenticationConverter;
import io.vertx.ext.web.RoutingContext;

/**
 * Extracts {@code client_secret_basic} credentials and converts them to an
 * {@link OAuth2ClientAuthenticationToken}.
 */
@Singleton
public final class ClientSecretBasicAuthenticationConverter
        implements AuthenticationConverter<OAuth2ClientAuthenticationToken> {

    private static final String BASIC = "Basic";

    @Override
    public OAuth2ClientAuthenticationToken convert(RoutingContext context) {
        String header = context.request().getHeader("Authorization");
        if (header == null) {
            return null;
        }

        String[] parts = header.split("\\s");
        if (!BASIC.equalsIgnoreCase(parts[0])) {
            return null;
        }
        if (parts.length != 2) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        byte[] decodedCredentials;
        try {
            decodedCredentials = Base64.getDecoder().decode(parts[1].getBytes(StandardCharsets.UTF_8));
        } catch (IllegalArgumentException exception) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), exception);
        }

        String credentialsString = new String(decodedCredentials, StandardCharsets.UTF_8);
        String[] clientCredentials = credentialsString.split(":", 2);
        if (clientCredentials.length != 2 || clientCredentials[0].isBlank() || clientCredentials[1].isBlank()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        try {
            String clientId = URLDecoder.decode(clientCredentials[0], StandardCharsets.UTF_8);
            String clientSecret = URLDecoder.decode(clientCredentials[1], StandardCharsets.UTF_8);
            return new OAuth2ClientAuthenticationToken(
                    clientId, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, clientSecret);
        } catch (IllegalArgumentException exception) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), exception);
        }
    }
}
