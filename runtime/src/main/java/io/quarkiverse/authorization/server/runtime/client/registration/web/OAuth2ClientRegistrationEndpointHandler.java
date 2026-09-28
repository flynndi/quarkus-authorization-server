package io.quarkiverse.authorization.server.runtime.client.registration.web;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.registration.OAuth2ClientRegistrationService;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

/** OAuth registration transport. Quarkus resolves bearer credentials even when anonymous registration is allowed. */
@Singleton
public final class OAuth2ClientRegistrationEndpointHandler implements Handler<RoutingContext> {
    private final OAuth2ClientRegistrationService service;
    private final OAuth2ClientRegistrationRequestParser parser;
    private final ProtocolExecutor executor;
    private final OAuth2ErrorHttpMessageConverter errors;

    @Inject
    public OAuth2ClientRegistrationEndpointHandler(OAuth2ClientRegistrationService service, ObjectMapper mapper,
            ProtocolExecutor executor, OAuth2ErrorHttpMessageConverter errors) {
        this.service = service;
        this.parser = new OAuth2ClientRegistrationRequestParser(mapper);
        this.executor = executor;
        this.errors = errors;
    }

    @Override
    public void handle(RoutingContext context) {
        context.response().putHeader(HttpHeaderNames.CACHE_CONTROL, "no-store").putHeader(HttpHeaderNames.PRAGMA, "no-cache");
        String contentType = context.request().getHeader(HttpHeaderNames.CONTENT_TYPE);
        String mediaType = contentType == null ? "" : contentType.split(";", 2)[0].trim().toLowerCase(java.util.Locale.ROOT);
        if (!"application/json".equals(mediaType) && !(mediaType.startsWith("application/") && mediaType.endsWith("+json"))) {
            context.response().setStatusCode(415).end();
            return;
        }
        QuarkusHttpUser.getSecurityIdentity(context, null).subscribe().with(identity -> {
            try {
                var principal = identity == null ? QuarkusSecurityIdentity.builder().setAnonymous(true).build() : identity;
                var request = this.parser.parse(context.body().asString(), principal);
                this.executor.execute(context, () -> this.service.register(request)).subscribe().with(
                        result -> context.response().setStatusCode(201)
                                .putHeader(HttpHeaderNames.CONTENT_TYPE, "application/json")
                                .end(new JsonObject(result).encode()),
                        failure -> this.fail(context, failure));
            } catch (RuntimeException failure) {
                this.fail(context, failure);
            }
        }, context::fail);
    }

    private void fail(RoutingContext context, Throwable failure) {
        OAuth2Error error = failure instanceof OAuth2AuthenticationException oauth ? oauth.getError()
                : new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR);
        int status = switch (error.getErrorCode()) {
            case OAuth2ErrorCodes.INVALID_TOKEN, OAuth2ErrorCodes.INVALID_CLIENT -> 401;
            case OAuth2ErrorCodes.INSUFFICIENT_SCOPE -> 403;
            case OAuth2ErrorCodes.SERVER_ERROR -> 500;
            default -> 400;
        };
        context.response().setStatusCode(status);
        if (status == 401 || status == 403)
            context.response().putHeader(HttpHeaderNames.WWW_AUTHENTICATE, "Bearer error=\"" + error.getErrorCode() + "\"");
        this.errors.write(error, context.response());
    }
}
