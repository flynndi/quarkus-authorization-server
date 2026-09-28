package io.quarkiverse.authorization.server.runtime.client.registration.web;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.security.OAuth2AccessTokenAuthenticationRequest;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.credential.TokenCredential;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/** Endpoint-scoped bearer extraction; token authentication is delegated to Quarkus Security. */
@Singleton
public final class ClientRegistrationAuthenticationMechanism implements HttpAuthenticationMechanism {

    public static final String AUTHENTICATION_SCHEME = "registration-bearer";
    private static final String ERROR_ATTRIBUTE = ClientRegistrationAuthenticationMechanism.class.getName() + ".error";
    private static final Pattern BEARER = Pattern.compile("^Bearer ([-a-zA-Z0-9._~+/]+=*)$", Pattern.CASE_INSENSITIVE);

    private final ClientRegistrationEndpointRequestMatcher requestMatcher;
    private final OAuth2ErrorHttpMessageConverter errorConverter;

    @Inject
    public ClientRegistrationAuthenticationMechanism(ClientRegistrationEndpointRequestMatcher requestMatcher,
            OAuth2ErrorHttpMessageConverter errorConverter) {
        this.requestMatcher = requestMatcher;
        this.errorConverter = errorConverter;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager manager) {
        if (!this.requestMatcher.matches(context)) {
            return Uni.createFrom().nullItem();
        }
        context.put(HttpAuthenticationMechanism.class.getName(), this);
        List<String> headers = context.request().headers().getAll(HttpHeaderNames.AUTHORIZATION);
        if (headers.isEmpty()) {
            return Uni.createFrom().nullItem();
        }
        String errorCode = null;
        var bearer = BEARER.matcher(headers.get(0));
        if (headers.size() != 1) {
            errorCode = OAuth2ErrorCodes.INVALID_REQUEST;
        } else if (!bearer.matches()) {
            errorCode = OAuth2ErrorCodes.INVALID_TOKEN;
        }
        if (errorCode != null) {
            context.put(ERROR_ATTRIBUTE, new OAuth2Error(errorCode));
            return Uni.createFrom().failure(new AuthenticationFailedException());
        }
        var request = new OAuth2AccessTokenAuthenticationRequest(new TokenCredential(bearer.group(1), "bearer"));
        HttpSecurityUtils.setRoutingContextAttribute(request, context);
        return manager.authenticate(request).onFailure(OAuth2AuthenticationException.class).transform(failure -> {
            OAuth2Error error = ((OAuth2AuthenticationException) failure).getError();
            context.put(ERROR_ATTRIBUTE, error);
            return new AuthenticationFailedException(failure.getMessage(), failure, Map.of());
        });
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        if (!this.requestMatcher.matches(context)) {
            return Uni.createFrom().nullItem();
        }
        OAuth2Error error = context.get(ERROR_ATTRIBUTE);
        return Uni.createFrom().item(new ChallengeData(
                error != null && OAuth2ErrorCodes.INVALID_REQUEST.equals(error.getErrorCode()) ? 400 : 401,
                HttpHeaderNames.WWW_AUTHENTICATE, error == null ? "Bearer" : "Bearer error=\"" + error.getErrorCode() + "\""));
    }

    /** Keep this Vert.x endpoint's JSON challenge when Quarkus REST forwards lazy authentication failures. */
    public void handleFailure(RoutingContext context) {
        if (!(context.failure() instanceof AuthenticationFailedException) || !this.requestMatcher.matches(context)) {
            context.next();
            return;
        }
        // Lazy identity resolution may report failure after Quarkus has already sent its challenge.
        if (context.response().headWritten())
            return;
        sendChallenge(context).subscribe().with(ignored -> {
        }, context::fail);
    }

    @Override
    public Uni<Boolean> sendChallenge(RoutingContext context) {
        if (!this.requestMatcher.matches(context)) {
            return Uni.createFrom().item(false);
        }
        OAuth2Error error = context.get(ERROR_ATTRIBUTE);
        context.response()
                .setStatusCode(error != null && OAuth2ErrorCodes.INVALID_REQUEST.equals(error.getErrorCode()) ? 400 : 401)
                .putHeader(HttpHeaderNames.WWW_AUTHENTICATE,
                        error == null ? "Bearer" : "Bearer error=\"" + error.getErrorCode() + "\"")
                .putHeader(HttpHeaderNames.CACHE_CONTROL, "no-store");
        if (error == null) {
            context.response().end();
        } else {
            this.errorConverter.write(new OAuth2Error(error.getErrorCode()), context.response());
        }
        return Uni.createFrom().item(true);
    }

    @Override
    public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
        return Set.of(OAuth2AccessTokenAuthenticationRequest.class);
    }

    @Override
    public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
        return Uni.createFrom().item(new HttpCredentialTransport(HttpCredentialTransport.Type.AUTHORIZATION, "Bearer",
                AUTHENTICATION_SCHEME));
    }

    @Override
    public int getPriority() {
        return 2200;
    }
}
