package io.quarkiverse.authorization.server.runtime.web;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2JwkSetHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

/**
 * Publishes the authorization server public JSON Web Key Set.
 */
@Singleton
public final class JwkSetEndpointHandler implements Handler<RoutingContext> {

    private final AuthorizationServerKeyManager keyManager;
    private final OAuth2JwkSetHttpMessageConverter jwkSetConverter;
    private final OAuth2ErrorHttpMessageConverter errorResponseConverter;

    @Inject
    public JwkSetEndpointHandler(AuthorizationServerKeyManager keyManager,
            OAuth2JwkSetHttpMessageConverter jwkSetConverter,
            OAuth2ErrorHttpMessageConverter errorResponseConverter) {
        this.keyManager = keyManager;
        this.jwkSetConverter = jwkSetConverter;
        this.errorResponseConverter = errorResponseConverter;
    }

    @Override
    public void handle(RoutingContext context) {
        try {
            this.jwkSetConverter.write(this.keyManager.getPublicJwks(), context.response());
        } catch (RuntimeException exception) {
            context.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code());
            this.errorResponseConverter.write(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), context.response());
        }
    }
}
