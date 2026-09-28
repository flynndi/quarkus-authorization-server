package io.quarkiverse.authorization.server.runtime.oidc.web;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.oidc.http.converter.OidcUserInfoHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.oidc.userinfo.OidcUserInfoService;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

/** Vert.x handler that returns UserInfo claims for the authenticated access token. */
@Singleton
public final class OidcUserInfoEndpointHandler implements Handler<RoutingContext> {
    private final OidcUserInfoService userInfoService;
    private final OidcUserInfoHttpMessageConverter userInfoConverter;
    private final OAuth2ErrorHttpMessageConverter errorConverter;
    private final OidcUserInfoAuthenticationMechanism authenticationMechanism;

    private final ProtocolExecutor executor;

    @Inject
    public OidcUserInfoEndpointHandler(
            ProtocolExecutor executor,
            OidcUserInfoService userInfoService,
            OidcUserInfoHttpMessageConverter userInfoConverter,
            OAuth2ErrorHttpMessageConverter errorConverter,
            OidcUserInfoAuthenticationMechanism authenticationMechanism) {
        this.executor = executor;
        this.userInfoService = userInfoService;
        this.userInfoConverter = userInfoConverter;
        this.errorConverter = errorConverter;
        this.authenticationMechanism = authenticationMechanism;
    }

    @Override
    public void handle(RoutingContext context) {
        context.response()
                .putHeader(HttpHeaderNames.CACHE_CONTROL, "no-store")
                .putHeader(HttpHeaderNames.PRAGMA, "no-cache");
        try {
            if (!(context.user() instanceof QuarkusHttpUser user)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
            }
            var principal = user.getSecurityIdentity();
            this.executor
                    .execute(context, () -> this.userInfoService.userInfo(principal))
                    .subscribe()
                    .with(
                            result -> {
                                try {
                                    this.userInfoConverter.write(result, context.response());
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
        String code = failure instanceof OAuth2AuthenticationException oauth
                ? oauth.getError().getErrorCode()
                : OAuth2ErrorCodes.SERVER_ERROR;
        int status = switch (code) {
            case OAuth2ErrorCodes.INVALID_TOKEN -> 401;
            case OAuth2ErrorCodes.INSUFFICIENT_SCOPE -> 403;
            case OAuth2ErrorCodes.INVALID_REQUEST -> 400;
            default -> 500;
        };
        context.response().setStatusCode(status);
        if (status != 500) {
            context.response()
                    .putHeader(
                            HttpHeaderNames.WWW_AUTHENTICATE,
                            this.authenticationMechanism.challenge(context, code));
        }
        this.errorConverter.write(new OAuth2Error(code), context.response());
    }
}
