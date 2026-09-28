package io.quarkiverse.authorization.server.runtime.client.web;

import java.util.List;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.web.authentication.AuthenticationConverter;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;

/** Extracts {@code client_secret_post} credentials from the form body. */
@Singleton
public final class ClientSecretPostAuthenticationConverter
        implements AuthenticationConverter<OAuth2ClientAuthenticationToken> {

    @Override
    public OAuth2ClientAuthenticationToken convert(RoutingContext context) {
        MultiMap parameters = context.request().formAttributes();
        List<String> secrets = parameters.getAll(OAuth2ParameterNames.CLIENT_SECRET);
        if (secrets.isEmpty()) {
            return null;
        }
        // Once a secret is submitted, malformed credentials cannot fall back to public identification.
        List<String> clientIds = parameters.getAll(OAuth2ParameterNames.CLIENT_ID);
        if (clientIds.size() != 1 || clientIds.get(0).isBlank()
                || secrets.size() != 1 || secrets.get(0).isBlank()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        // Vert.x has already decoded form values; decoding again would corrupt '+' and '%' in secrets.
        return new OAuth2ClientAuthenticationToken(
                clientIds.get(0), ClientAuthenticationMethod.CLIENT_SECRET_POST, secrets.get(0));
    }
}
