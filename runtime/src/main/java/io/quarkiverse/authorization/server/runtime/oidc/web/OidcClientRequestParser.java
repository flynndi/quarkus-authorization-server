package io.quarkiverse.authorization.server.runtime.oidc.web;

import java.util.List;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationRequest;
import io.quarkiverse.authorization.server.runtime.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.oidc.registration.OidcClientConfigurationRequest;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.ext.web.RoutingContext;

/**
 * Parses POST registration and GET client configuration requests using the Quarkus HTTP
 * security identity.
 */
public final class OidcClientRequestParser {

    private final OidcClientRegistrationHttpMessageConverter messageConverter;

    public OidcClientRequestParser(OidcClientRegistrationHttpMessageConverter messageConverter) {
        this.messageConverter = messageConverter;
    }

    public OidcClientRegistrationRequest parseRegistration(RoutingContext context) {
        var principal = principal(context);
        try {
            return new OidcClientRegistrationRequest(
                    principal, this.messageConverter.read(context.body().asString()));
        } catch (IllegalArgumentException exception) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_REQUEST,
                            "Unable to read the OpenID Client Registration",
                            null));
        }
    }

    public OidcClientConfigurationRequest parseConfiguration(RoutingContext context) {
        var principal = principal(context);
        List<String> clientIds = context.queryParam(OAuth2ParameterNames.CLIENT_ID);
        if (clientIds.size() != 1 || clientIds.get(0).isBlank()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return new OidcClientConfigurationRequest(principal, clientIds.get(0));
    }

    private static SecurityIdentity principal(RoutingContext context) {
        if (!(context.user() instanceof QuarkusHttpUser user)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }
        return user.getSecurityIdentity();
    }
}
