package io.quarkiverse.authorization.server.runtime.client.web;

import java.util.Map;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.JwtClientAssertionAuthenticationRequest;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.client.authentication.X509ClientCertificateAuthenticationRequest;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.mutiny.Uni;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;

/**
 * Quarkus HTTP authentication mechanism that parses OAuth client credentials and delegates to IdentityProviderManager.
 */
@Singleton
public final class OAuth2ClientAuthenticationMechanism implements HttpAuthenticationMechanism {

    public static final String AUTHENTICATION_SCHEME = "oauth2-client";
    // Quarkus Basic authentication uses priority 2000; OAuth client Basic must own the token endpoint first.
    private static final int PRIORITY = 2100;
    private static final String CHALLENGE = "Basic realm=\"oauth2/client\"";

    private final ClientSecretBasicAuthenticationConverter basicAuthenticationConverter;
    private final ClientSecretPostAuthenticationConverter postAuthenticationConverter;
    private final JwtClientAssertionAuthenticationConverter jwtAuthenticationConverter;
    private final X509ClientCertificateAuthenticationConverter certificateAuthenticationConverter;
    private final PublicClientAuthenticationConverter publicClientAuthenticationConverter;
    private final OAuth2ClientAuthenticationRequestMatcher requestMatcher;
    private final OAuth2ErrorHttpMessageConverter errorHttpResponseConverter;

    @Inject
    public OAuth2ClientAuthenticationMechanism(
            ClientSecretBasicAuthenticationConverter basicAuthenticationConverter,
            ClientSecretPostAuthenticationConverter postAuthenticationConverter,
            JwtClientAssertionAuthenticationConverter jwtAuthenticationConverter,
            X509ClientCertificateAuthenticationConverter certificateAuthenticationConverter,
            PublicClientAuthenticationConverter publicClientAuthenticationConverter,
            OAuth2ClientAuthenticationRequestMatcher requestMatcher,
            OAuth2ErrorHttpMessageConverter errorHttpResponseConverter) {
        this.basicAuthenticationConverter = basicAuthenticationConverter;
        this.postAuthenticationConverter = postAuthenticationConverter;
        this.jwtAuthenticationConverter = jwtAuthenticationConverter;
        this.certificateAuthenticationConverter = certificateAuthenticationConverter;
        this.publicClientAuthenticationConverter = publicClientAuthenticationConverter;
        this.requestMatcher = requestMatcher;
        this.errorHttpResponseConverter = errorHttpResponseConverter;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
        if (!this.requestMatcher.matches(context)) {
            return Uni.createFrom().nullItem();
        }
        context.put(HttpAuthenticationMechanism.class.getName(), this);
        AuthenticationRequest authentication;
        try {
            MultiMap parameters = context.request().formAttributes();
            int authorizationHeaders = context.request().headers().getAll(HttpHeaderNames.AUTHORIZATION).size();
            boolean secret = parameters.contains(OAuth2ParameterNames.CLIENT_SECRET);
            boolean assertion = parameters.contains(OAuth2ParameterNames.CLIENT_ASSERTION)
                    || parameters.contains(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE);
            // RFC 6749 section 2.3: a request must not use more than one authentication method.
            if (authorizationHeaders > 1
                    || (authorizationHeaders > 0 && (secret || assertion))
                    || (secret && assertion)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
            authentication = this.jwtAuthenticationConverter.convert(context);
            if (authentication == null) {
                authentication = this.basicAuthenticationConverter.convert(context);
            }
            if (authentication == null) {
                authentication = this.postAuthenticationConverter.convert(context);
            }
            // An explicit HTTP credential selects that method. A TLS certificate alone is transport state.
            if (authentication == null && authorizationHeaders == 0) {
                authentication = this.certificateAuthenticationConverter.convert(context);
            }
            if (authentication == null && this.requestMatcher.allowsPublicClient(context)) {
                authentication = this.publicClientAuthenticationConverter.convert(context);
            }
        } catch (OAuth2AuthenticationException exception) {
            return Uni.createFrom().failure(OAuth2ClientAuthenticationMechanism.toAuthenticationFailedException(exception));
        }
        if (authentication == null) {
            return Uni.createFrom().failure(OAuth2ClientAuthenticationMechanism.toAuthenticationFailedException(
                    new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)));
        }

        HttpSecurityUtils.setRoutingContextAttribute(authentication, context);
        return identityProviderManager.authenticate(authentication)
                .onFailure(OAuth2AuthenticationException.class)
                .transform(failure -> OAuth2ClientAuthenticationMechanism
                        .toAuthenticationFailedException((OAuth2AuthenticationException) failure));
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        if (!this.requestMatcher.matches(context)) {
            return Uni.createFrom().nullItem();
        }
        AuthenticationFailedException failure = HttpSecurityUtils.getAuthenticationFailureFromEvent(context);
        OAuth2Error error = failure == null ? null : failure.getAttribute(OAuth2Error.class.getName());
        if (error != null && !OAuth2ErrorCodes.INVALID_CLIENT.equals(error.getErrorCode())) {
            return Uni.createFrom().item(new ChallengeData(HttpResponseStatus.BAD_REQUEST.code()));
        }
        return Uni.createFrom().item(new ChallengeData(
                HttpResponseStatus.UNAUTHORIZED.code(),
                HttpHeaderNames.WWW_AUTHENTICATE,
                CHALLENGE));
    }

    /** Keep client-authentication failures on protected OAuth routes out of REST's generic exception mapping. */
    public void handleFailure(RoutingContext context) {
        if (!(context.failure() instanceof AuthenticationFailedException failure) || !this.requestMatcher.matches(context)) {
            context.next();
            return;
        }
        HttpSecurityUtils.addAuthenticationFailureToEvent(failure, context);
        sendChallenge(context).subscribe().with(ignored -> {
        }, context::fail);
    }

    @Override
    public Uni<Boolean> sendChallenge(RoutingContext context) {
        if (!this.requestMatcher.matches(context)) {
            return Uni.createFrom().item(false);
        }
        AuthenticationFailedException authenticationFailure = HttpSecurityUtils.getAuthenticationFailureFromEvent(context);
        OAuth2Error error = authenticationFailure != null
                ? authenticationFailure.getAttribute(OAuth2Error.class.getName())
                : null;
        if (error == null) {
            return HttpAuthenticationMechanism.super.sendChallenge(context);
        }

        boolean invalidClient = OAuth2ErrorCodes.INVALID_CLIENT.equals(error.getErrorCode());
        context.response().setStatusCode(invalidClient
                ? HttpResponseStatus.UNAUTHORIZED.code()
                : HttpResponseStatus.BAD_REQUEST.code());
        if (invalidClient) {
            context.response().putHeader(HttpHeaderNames.WWW_AUTHENTICATE, CHALLENGE);
        }
        // Expose only the OAuth error code; keep client-authentication failure details out of the response.
        this.errorHttpResponseConverter.write(new OAuth2Error(error.getErrorCode()), context.response());
        return Uni.createFrom().item(true);
    }

    @Override
    public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
        return Set.of(OAuth2ClientAuthenticationToken.class, JwtClientAssertionAuthenticationRequest.class,
                X509ClientCertificateAuthenticationRequest.class);
    }

    @Override
    public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
        return Uni.createFrom().item(new HttpCredentialTransport(
                HttpCredentialTransport.Type.AUTHORIZATION,
                "Basic",
                AUTHENTICATION_SCHEME));
    }

    @Override
    public int getPriority() {
        return PRIORITY;
    }

    private static AuthenticationFailedException toAuthenticationFailedException(
            OAuth2AuthenticationException exception) {
        // HTTP error transport belongs to the Quarkus mechanism, not to the OAuth domain exception.
        return new AuthenticationFailedException(
                exception.getMessage(), exception, Map.of(OAuth2Error.class.getName(), exception.getError()));
    }
}
