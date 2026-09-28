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

/** Extracts a public client's identifier independently of the requested grant. */
@Singleton
public final class PublicClientAuthenticationConverter
        implements AuthenticationConverter<OAuth2ClientAuthenticationToken> {

    @Override
    public OAuth2ClientAuthenticationToken convert(RoutingContext context) {
        MultiMap parameters = context.request().formAttributes();
        // An unsupported credential must not silently fall back to public client identification.
        if (context.request().getHeader("Authorization") != null
                || parameters.contains(OAuth2ParameterNames.CLIENT_SECRET)
                || parameters.contains(OAuth2ParameterNames.CLIENT_ASSERTION)
                || parameters.contains(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE)) {
            return null;
        }
        List<String> clientIds = parameters.getAll(OAuth2ParameterNames.CLIENT_ID);
        if (clientIds.isEmpty()) {
            return null;
        }
        if (clientIds.size() != 1 || clientIds.get(0).isBlank()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return new OAuth2ClientAuthenticationToken(
                clientIds.get(0), ClientAuthenticationMethod.NONE, null);
    }
}
