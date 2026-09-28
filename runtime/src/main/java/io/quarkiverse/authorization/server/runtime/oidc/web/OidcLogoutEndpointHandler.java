package io.quarkiverse.authorization.server.runtime.oidc.web;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.session.OidcSessionManager;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.oidc.logout.OidcLogoutResult;
import io.quarkiverse.authorization.server.runtime.oidc.logout.OidcLogoutService;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

/**
 * Vert.x handler that ends the OIDC browser session and redirects to a validated logout URI.
 * Issued OAuth tokens and stored consent remain unchanged.
 */
@Singleton
public final class OidcLogoutEndpointHandler implements Handler<RoutingContext> {
    private final OidcLogoutService logoutService;
    private final OidcLogoutRequestParser requestParser;
    private final OidcSessionManager sessionManager;
    private final OAuth2ErrorHttpMessageConverter errorConverter;

    private final ProtocolExecutor executor;

    @Inject
    public OidcLogoutEndpointHandler(
            ProtocolExecutor executor,
            OidcLogoutService logoutService,
            Instance<OidcSessionManager> sessionManagers,
            OAuth2ErrorHttpMessageConverter errorConverter) {
        this.executor = executor;
        this.logoutService = logoutService;
        this.sessionManager = sessionManagers.isUnsatisfied() ? null : sessionManagers.get();
        this.requestParser = new OidcLogoutRequestParser(this.sessionManager);
        this.errorConverter = errorConverter;
    }

    @Override
    public void handle(RoutingContext context) {
        context.response().putHeader("Cache-Control", "no-store").putHeader("Pragma", "no-cache");
        if (context.request().method() == HttpMethod.POST) {
            String contentType = context.request().getHeader("Content-Type");
            if (contentType == null
                    || !contentType
                            .split(";", 2)[0]
                            .trim()
                            .equalsIgnoreCase("application/x-www-form-urlencoded")) {
                context.response().setStatusCode(415).end();
                return;
            }
        }
        try {
            // Resolve lazy HTTP authentication too; a permit rule alone does not load the current
            // Form identity.
            QuarkusHttpUser.getSecurityIdentity(context, null)
                    .chain(
                            principal -> {
                                if (principal != null) {
                                    context.setUser(new QuarkusHttpUser(principal));
                                }
                                var authentication = this.requestParser.parse(context);
                                return this.executor.execute(
                                        context, () -> this.logoutService.validate(authentication));
                            })
                    .subscribe()
                    .with(
                            authentication -> {
                                try {
                                    performLogout(context, authentication);
                                } catch (RuntimeException exception) {
                                    sendError(context, exception);
                                }
                            },
                            failure -> sendError(context, failure));
        } catch (OAuth2AuthenticationException exception) {
            sendError(context, exception);
        }
    }

    private void performLogout(RoutingContext context, OidcLogoutResult result) {
        if (!result.principal().isAnonymous() && this.sessionManager != null) {
            this.sessionManager.logout(context, result.principal());
        }
        String redirect = result.postLogoutRedirectUri();
        if (redirect == null || redirect.isBlank()) {
            redirect = "/";
        } else if (result.state() != null && !result.state().isBlank()) {
            String separator = redirect.endsWith("?") || redirect.endsWith("&")
                    ? ""
                    : redirect.contains("?") ? "&" : "?";
            redirect += separator
                    + "state="
                    + URLEncoder.encode(result.state(), StandardCharsets.UTF_8);
        }
        context.response().setStatusCode(302).putHeader("Location", redirect).end();
    }

    private void sendError(RoutingContext context, Throwable failure) {
        OAuth2Error error = failure instanceof OAuth2AuthenticationException exception
                ? exception.getError()
                : new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR);
        context.response()
                .setStatusCode(failure instanceof OAuth2AuthenticationException ? 400 : 500);
        this.errorConverter.write(error, context.response());
    }
}
