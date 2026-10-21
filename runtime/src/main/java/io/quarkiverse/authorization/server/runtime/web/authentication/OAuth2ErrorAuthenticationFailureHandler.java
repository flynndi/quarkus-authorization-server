package io.quarkiverse.authorization.server.runtime.web.authentication;

import org.jboss.logging.Logger;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.vertx.ext.web.RoutingContext;

/**
 * Writes protocol errors and logs internal failures without exposing their details in the response.
 */
public final class OAuth2ErrorAuthenticationFailureHandler {

    private static final Logger LOG = Logger.getLogger(OAuth2ErrorAuthenticationFailureHandler.class);

    private final OAuth2ErrorHttpMessageConverter errorResponseConverter;

    public OAuth2ErrorAuthenticationFailureHandler(OAuth2ErrorHttpMessageConverter errorResponseConverter) {
        this.errorResponseConverter = errorResponseConverter;
    }

    public void onAuthenticationFailure(RoutingContext context, Throwable failure) {
        OAuth2Error error = failure instanceof OAuth2AuthenticationException authenticationException
                ? authenticationException.getError()
                : new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR);
        if (OAuth2ErrorCodes.SERVER_ERROR.equals(error.getErrorCode())) {
            LOG.error("OAuth 2.0 request failed", failure);
            context.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code());
            // An explicitly reported server_error may also contain sensitive implementation details.
            this.errorResponseConverter.write(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), context.response());
        } else {
            context.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code());
            this.errorResponseConverter.write(error, context.response());
        }
    }
}
