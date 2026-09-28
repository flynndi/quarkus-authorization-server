package io.quarkiverse.authorization.server.runtime.oidc.web;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofRequest;
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

/** Endpoint-scoped Bearer/DPoP extraction; token authentication belongs to Quarkus Security. */
@Singleton
public final class OidcUserInfoAuthenticationMechanism implements HttpAuthenticationMechanism {
    public static final String AUTHENTICATION_SCHEME = "oauth2-access-token";
    private static final String ERROR_ATTRIBUTE = OidcUserInfoAuthenticationMechanism.class.getName() + ".error";
    private static final Pattern AUTHORIZATION = Pattern.compile("^(Bearer|DPoP) +([-a-zA-Z0-9._~+/]+=*)$",
            Pattern.CASE_INSENSITIVE);
    private final OidcUserInfoEndpointRequestMatcher requestMatcher;
    private final OAuth2ErrorHttpMessageConverter errorConverter;
    private final String dpopChallenge;

    @Inject
    public OidcUserInfoAuthenticationMechanism(
            OidcUserInfoEndpointRequestMatcher requestMatcher,
            OAuth2ErrorHttpMessageConverter errorConverter,
            AuthorizationServerRuntimeConfig config) {
        this.requestMatcher = requestMatcher;
        this.errorConverter = errorConverter;
        this.dpopChallenge = "DPoP algs=\""
                + config.dpop().proofAlgorithms().stream()
                        .map(algorithm -> algorithm.getName())
                        .sorted()
                        .collect(Collectors.joining(" "))
                + "\"";
    }

    @Override
    public Uni<SecurityIdentity> authenticate(
            RoutingContext context, IdentityProviderManager manager) {
        if (!this.requestMatcher.matches(context)) {
            return Uni.createFrom().nullItem();
        }
        context.put(HttpAuthenticationMechanism.class.getName(), this);
        List<String> headers = context.request().headers().getAll(HttpHeaderNames.AUTHORIZATION);
        if (headers.isEmpty()) {
            return Uni.createFrom().nullItem();
        }
        String errorCode = null;
        var authorization = AUTHORIZATION.matcher(headers.getFirst());
        if (headers.size() != 1) {
            errorCode = OAuth2ErrorCodes.INVALID_REQUEST;
        } else if (!authorization.matches()) {
            errorCode = OAuth2ErrorCodes.INVALID_TOKEN;
        }
        if (errorCode != null) {
            context.put(ERROR_ATTRIBUTE, new OAuth2Error(errorCode));
            return Uni.createFrom().failure(new AuthenticationFailedException());
        }
        // Parsing can fail synchronously (e.g. duplicate DPoP headers); route it through the same
        // Quarkus authentication failure/challenge path as asynchronous proof verification.
        return Uni.createFrom()
                .deferred(
                        () -> {
                            String type = authorization.group(1).toLowerCase(Locale.ROOT);
                            var proof = OAuth2AccessTokenAuthenticationRequest.DPOP.equals(type)
                                    ? DPoPProofRequest.from(context)
                                    : null;
                            var request = new OAuth2AccessTokenAuthenticationRequest(
                                    new TokenCredential(authorization.group(2), type),
                                    proof);
                            HttpSecurityUtils.setRoutingContextAttribute(request, context);
                            return manager.authenticate(request);
                        })
                .onFailure(OAuth2AuthenticationException.class)
                .transform(
                        failure -> {
                            OAuth2Error error = ((OAuth2AuthenticationException) failure).getError();
                            context.put(ERROR_ATTRIBUTE, error);
                            return new AuthenticationFailedException(
                                    failure.getMessage(), failure, Map.of());
                        });
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        if (!this.requestMatcher.matches(context)) {
            return Uni.createFrom().nullItem();
        }
        OAuth2Error error = context.get(ERROR_ATTRIBUTE);
        return Uni.createFrom()
                .item(
                        new ChallengeData(
                                error != null
                                        && OAuth2ErrorCodes.INVALID_REQUEST.equals(
                                                error.getErrorCode())
                                                        ? 400
                                                        : 401,
                                HttpHeaderNames.WWW_AUTHENTICATE,
                                challenge(context, error == null ? null : error.getErrorCode())));
    }

    /**
     * Preserve the endpoint JSON challenge when Quarkus REST forwards lazy authentication failures.
     */
    public void handleFailure(RoutingContext context) {
        if (!(context.failure() instanceof AuthenticationFailedException)
                || !this.requestMatcher.matches(context)) {
            context.next();
            return;
        }
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
                .setStatusCode(
                        error != null
                                && OAuth2ErrorCodes.INVALID_REQUEST.equals(
                                        error.getErrorCode())
                                                ? 400
                                                : 401)
                .putHeader(
                        HttpHeaderNames.WWW_AUTHENTICATE,
                        challenge(context, error == null ? null : error.getErrorCode()))
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
        return Uni.createFrom()
                .item(
                        new HttpCredentialTransport(
                                HttpCredentialTransport.Type.AUTHORIZATION,
                                OAuth2AccessTokenAuthenticationRequest.DPOP.equals(
                                        requestScheme(context))
                                                ? "DPoP"
                                                : "Bearer",
                                AUTHENTICATION_SCHEME));
    }

    /** Both authentication and UserInfo authorization failures use the attempted wire scheme. */
    String challenge(RoutingContext context, String errorCode) {
        String error = errorCode == null ? "" : " error=\"" + errorCode + "\"";
        String dpop = this.dpopChallenge + (errorCode == null ? "" : "," + error);
        String scheme = requestScheme(context);
        if (OAuth2AccessTokenAuthenticationRequest.DPOP.equals(scheme))
            return dpop;
        if (OAuth2AccessTokenAuthenticationRequest.BEARER.equals(scheme))
            return "Bearer" + error;
        return "Bearer" + error + ", " + dpop;
    }

    private static String requestScheme(RoutingContext context) {
        List<String> headers = context.request().headers().getAll(HttpHeaderNames.AUTHORIZATION);
        return headers.size() == 1
                ? headers.getFirst().split(" ", 2)[0].toLowerCase(Locale.ROOT)
                : null;
    }

    @Override
    public int getPriority() {
        return 2200;
    }
}
