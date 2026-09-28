package io.quarkiverse.authorization.server.runtime.client.web;

import java.util.List;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.JwtClientAssertionAuthenticationRequest;
import io.quarkiverse.authorization.server.runtime.web.authentication.AuthenticationConverter;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;

/** Parses assertion credentials without trusting claims or selecting a signing algorithm. */
@Singleton
public final class JwtClientAssertionAuthenticationConverter
        implements AuthenticationConverter<JwtClientAssertionAuthenticationRequest> {
    @Override
    public JwtClientAssertionAuthenticationRequest convert(RoutingContext context) {
        MultiMap parameters = context.request().formAttributes();
        if (!parameters.contains(OAuth2ParameterNames.CLIENT_ASSERTION)
                && !parameters.contains(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE))
            return null;
        List<String> types = parameters.getAll(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE);
        List<String> assertions = parameters.getAll(OAuth2ParameterNames.CLIENT_ASSERTION);
        List<String> clientIds = parameters.getAll(OAuth2ParameterNames.CLIENT_ID);
        if (types.size() != 1 || types.getFirst().isBlank()
                || assertions.size() != 1 || assertions.getFirst().isBlank()
                || clientIds.size() != 1 || clientIds.getFirst().isBlank()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        if (!JwtClientAssertionAuthenticationRequest.ASSERTION_TYPE.equals(types.getFirst())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        return new JwtClientAssertionAuthenticationRequest(clientIds.getFirst(), assertions.getFirst());
    }
}
