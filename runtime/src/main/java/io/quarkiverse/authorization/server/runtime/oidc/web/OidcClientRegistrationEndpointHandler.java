package io.quarkiverse.authorization.server.runtime.oidc.web;

import java.util.Locale;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.oidc.registration.OidcClientConfigurationService;
import io.quarkiverse.authorization.server.runtime.oidc.registration.OidcClientRegistrationService;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

/** Vert.x handler for OIDC client registration and authenticated client configuration retrieval. */
@Singleton
public final class OidcClientRegistrationEndpointHandler implements Handler<RoutingContext> {

    private final OidcClientRequestParser requestParser;
    private final OidcClientRegistrationService registrationService;
    private final OidcClientConfigurationService configurationService;
    private final OidcClientRegistrationHttpMessageConverter messageConverter;
    private final OAuth2ErrorHttpMessageConverter errorConverter;

    private final ProtocolExecutor executor;

    @Inject
    public OidcClientRegistrationEndpointHandler(
            ProtocolExecutor executor,
            OidcClientRegistrationService registrationService,
            OidcClientConfigurationService configurationService,
            OidcClientRegistrationHttpMessageConverter messageConverter,
            OAuth2ErrorHttpMessageConverter errorConverter) {
        this.executor = executor;
        this.requestParser = new OidcClientRequestParser(messageConverter);
        this.registrationService = registrationService;
        this.configurationService = configurationService;
        this.messageConverter = messageConverter;
        this.errorConverter = errorConverter;
    }

    @Override
    public void handle(RoutingContext context) {
        context.response()
                .putHeader(HttpHeaderNames.CACHE_CONTROL, "no-store")
                .putHeader(HttpHeaderNames.PRAGMA, "no-cache");
        boolean registration = context.request().method() == HttpMethod.POST;
        if (registration) {
            String contentType = context.request().getHeader(HttpHeaderNames.CONTENT_TYPE);
            String mediaType = contentType == null
                    ? ""
                    : contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
            if (!mediaType.equals("application/json")
                    && !(mediaType.startsWith("application/") && mediaType.endsWith("+json"))) {
                context.response().setStatusCode(415);
                this.errorConverter.write(
                        new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), context.response());
                return;
            }
        }
        try {
            if (!registration && context.request().method() != HttpMethod.GET) {
                context.next();
                return;
            }
            Uni<OidcClientRegistration> result;
            if (registration) {
                var request = this.requestParser.parseRegistration(context);
                result = this.executor.execute(
                        context, () -> this.registrationService.register(request));
            } else {
                var request = this.requestParser.parseConfiguration(context);
                result = this.executor.execute(
                        context, () -> this.configurationService.read(request));
            }
            result.subscribe()
                    .with(
                            registrationResult -> {
                                try {
                                    context.response().setStatusCode(registration ? 201 : 200);
                                    this.messageConverter.write(
                                            registrationResult, context.response());
                                } catch (RuntimeException failure) {
                                    sendError(context, failure);
                                }
                            },
                            failure -> sendError(context, failure));
        } catch (RuntimeException failure) {
            sendError(context, failure);
        }
    }

    private void sendError(RoutingContext context, Throwable failure) {
        OAuth2Error error = failure instanceof OAuth2AuthenticationException oauth
                ? oauth.getError()
                : new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR);
        int status = switch (error.getErrorCode()) {
            case OAuth2ErrorCodes.INVALID_TOKEN, OAuth2ErrorCodes.INVALID_CLIENT -> 401;
            case OAuth2ErrorCodes.INSUFFICIENT_SCOPE -> 403;
            case OAuth2ErrorCodes.SERVER_ERROR -> 500;
            default -> 400;
        };
        context.response().setStatusCode(status);
        if (status == 401 || status == 403) {
            context.response()
                    .putHeader(
                            HttpHeaderNames.WWW_AUTHENTICATE,
                            "Bearer error=\"" + error.getErrorCode() + "\"");
        }
        this.errorConverter.write(error, context.response());
    }
}
