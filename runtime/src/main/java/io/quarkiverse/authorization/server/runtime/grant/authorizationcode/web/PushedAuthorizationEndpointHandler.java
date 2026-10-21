package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationRequestProcessor;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

/** HTTP transport for PAR; Quarkus authenticates the client before this handler runs. */
@Singleton
public final class PushedAuthorizationEndpointHandler implements Handler<RoutingContext> {
    private final AuthorizationRequestParser parser = new AuthorizationRequestParser();
    private final AuthorizationRequestProcessor processor;
    private final ProtocolExecutor executor;
    private final OAuth2ErrorAuthenticationFailureHandler failures;

    @Inject
    public PushedAuthorizationEndpointHandler(AuthorizationRequestProcessor processor, ProtocolExecutor executor,
            OAuth2ErrorHttpMessageConverter errors) {
        this.processor = processor;
        this.executor = executor;
        this.failures = new OAuth2ErrorAuthenticationFailureHandler(errors);
    }

    @Override
    public void handle(RoutingContext context) {
        if (context.request().method() != io.vertx.core.http.HttpMethod.POST) {
            context.response().setStatusCode(405).putHeader(HttpHeaders.ALLOW, "POST").end();
            return;
        }
        String contentType = context.request().getHeader(HttpHeaders.CONTENT_TYPE);
        if (contentType == null || !"application/x-www-form-urlencoded".equalsIgnoreCase(contentType.split(";", 2)[0].trim())) {
            context.response().setStatusCode(415).end();
            return;
        }
        try {
            var request = this.parser.parsePushed(context);
            this.executor.execute(context, () -> this.processor.push(request)).subscribe().with(
                    result -> context.response().setStatusCode(201).putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                            .putHeader(HttpHeaders.CACHE_CONTROL, "no-store")
                            .putHeader(io.netty.handler.codec.http.HttpHeaderNames.PRAGMA, "no-cache")
                            .end(new JsonObject().put(OAuth2ParameterNames.REQUEST_URI, result.requestUri())
                                    .put(OAuth2ParameterNames.EXPIRES_IN, result.expiresIn()).encode()),
                    failure -> this.fail(context, failure));
        } catch (RuntimeException failure) {
            this.fail(context, failure);
        }
    }

    private void fail(RoutingContext context, Throwable failure) {
        // PAR errors are JSON responses, including validation exceptions carrying a trusted callback.
        this.failures.onAuthenticationFailure(context, failure);
    }
}
