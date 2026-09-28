package io.quarkiverse.authorization.server.runtime.web.authentication;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.vertx.ext.web.RoutingContext;

/**
 * Handles an {@link OAuth2AuthenticationException} by returning an OAuth 2.0 Error Response.
 */
public final class OAuth2ErrorAuthenticationFailureHandler {

    private final OAuth2ErrorHttpMessageConverter errorResponseConverter;

    public OAuth2ErrorAuthenticationFailureHandler(OAuth2ErrorHttpMessageConverter errorResponseConverter) {
        this.errorResponseConverter = errorResponseConverter;
    }

    public void onAuthenticationFailure(RoutingContext context,
            OAuth2AuthenticationException authenticationException) {
        context.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code());
        this.errorResponseConverter.write(authenticationException.getError(), context.response());
    }
}
