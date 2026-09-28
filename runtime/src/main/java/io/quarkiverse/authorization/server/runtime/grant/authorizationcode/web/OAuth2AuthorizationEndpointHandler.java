package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequest;
import io.quarkiverse.authorization.server.grant.authorizationcode.ConsentSubmission;
import io.quarkiverse.authorization.server.grant.authorizationcode.OAuth2AuthorizationConsentPage;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.session.OidcSessionManager;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationConsentProcessor;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationOutcome;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationRedirect;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationRequestException;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationRequestProcessor;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.VertxContextSupport;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticator;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

/** Vert.x handler for authorization requests, login challenges, consent pages and code redirects. */
@Singleton
public final class OAuth2AuthorizationEndpointHandler implements Handler<RoutingContext> {

    private static final String FORM_URLENCODED = "application/x-www-form-urlencoded";

    private final AuthorizationRequestParser authorizationCodeRequestAuthenticationConverter = new AuthorizationRequestParser();
    private final ConsentSubmissionParser authorizationConsentAuthenticationConverter = new ConsentSubmissionParser();
    private final AuthorizationRequestProcessor authorizationRequestProcessor;
    private final AuthorizationConsentProcessor authorizationConsentProcessor;
    private final OAuth2AuthorizationConsentPage authorizationConsentPage;
    private final OAuth2ErrorAuthenticationFailureHandler authenticationFailureHandler;
    private final HttpAuthenticator httpAuthenticator;

    private OidcSessionManager sessionManager;

    @Inject
    void configureSessionManager(Instance<OidcSessionManager> sessionManagers) {
        this.sessionManager = sessionManagers.isUnsatisfied() ? null : sessionManagers.get();
    }

    @Inject
    public OAuth2AuthorizationEndpointHandler(
            AuthorizationRequestProcessor authorizationRequestProcessor,
            AuthorizationConsentProcessor authorizationConsentProcessor,
            OAuth2AuthorizationConsentPage authorizationConsentPage,
            HttpAuthenticator httpAuthenticator,
            OAuth2ErrorHttpMessageConverter errorResponseConverter) {
        this.authorizationRequestProcessor = authorizationRequestProcessor;
        this.authorizationConsentProcessor = authorizationConsentProcessor;
        this.authorizationConsentPage = authorizationConsentPage;
        this.httpAuthenticator = httpAuthenticator;
        this.authenticationFailureHandler = new OAuth2ErrorAuthenticationFailureHandler(errorResponseConverter);
    }

    @Override
    public void handle(RoutingContext context) {
        if (context.request().method() == HttpMethod.POST
                && !OAuth2AuthorizationEndpointHandler
                        .isFormUrlEncoded(context.request().getHeader(HttpHeaders.CONTENT_TYPE))) {
            context.response()
                    .setStatusCode(HttpResponseStatus.UNSUPPORTED_MEDIA_TYPE.code())
                    .end();
            return;
        }

        // Permit initial requests without forcing a login challenge. Resolve an existing identity
        // explicitly as well, so Form cookies work with quarkus.http.auth.proactive=false.
        QuarkusHttpUser.getSecurityIdentity(context, null).subscribe().with(identity -> {
            if (identity != null)
                context.setUser(new QuarkusHttpUser(identity));
            this.handleRequest(context);
        }, context::fail);
    }

    private void handleRequest(RoutingContext context) {
        try {
            if (this.sessionManager != null && context.user() instanceof QuarkusHttpUser user
                    && !user.getSecurityIdentity().isAnonymous()) {
                SecurityIdentity principal = user.getSecurityIdentity();
                SessionInformation session = this.sessionManager.getSessionInformation(context, principal);
                if (session != null) {
                    context.setUser(
                            new QuarkusHttpUser(
                                    QuarkusSecurityIdentity.builder(principal)
                                            .addAttribute(
                                                    SessionInformation.class.getName(), session)
                                            .build()));
                }
            }
            AuthorizationRequest authentication = this.authorizationCodeRequestAuthenticationConverter.parse(context);
            if (authentication != null) {
                VertxContextSupport.executeBlocking(
                        () -> this.authorizationRequestProcessor.authorize(authentication))
                        .subscribe()
                        .with(
                                authenticationResult -> this.handleAuthorizationResult(context, authenticationResult),
                                failure -> this.handleAuthenticationFailure(context, failure));
                return;
            }

            ConsentSubmission consentAuthentication = this.authorizationConsentAuthenticationConverter.parse(context);
            if (consentAuthentication == null) {
                throw new AuthorizationRequestException(
                        new OAuth2Error(
                                OAuth2ErrorCodes.INVALID_REQUEST,
                                "OAuth 2.0 Parameter: " + OAuth2ParameterNames.RESPONSE_TYPE,
                                "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1"),
                        null);
            }

            VertxContextSupport.executeBlocking(
                    () -> this.authorizationConsentProcessor.consent(consentAuthentication))
                    .subscribe()
                    .with(
                            authenticationResult -> this.handleAuthorizationResult(context, authenticationResult),
                            failure -> this.handleAuthenticationFailure(context, failure));
        } catch (AuthorizationRequestException exception) {
            this.sendErrorResponse(context, exception);
        } catch (OAuth2AuthenticationException exception) {
            this.authenticationFailureHandler.onAuthenticationFailure(context, exception);
        }
    }

    private void handleAuthorizationResult(RoutingContext context, AuthorizationOutcome outcome) {
        switch (outcome) {
            case AuthorizationOutcome.ConsentRequired consent ->
                this.authorizationConsentPage.displayConsent(
                        context,
                        consent.clientId(),
                        consent.principal(),
                        consent.requestedScopes(),
                        consent.authorizedScopes(),
                        consent.state());
            case AuthorizationOutcome.CodeIssued issued ->
                this.sendAuthorizationResponse(context, issued);
            case AuthorizationOutcome.LoginRequired ignored -> this.challengeLogin(context);
        }
    }

    private void challengeLogin(RoutingContext context) {
        if (context.request().method() == HttpMethod.POST) {
            // Quarkus Form saves a URL, not a POST body. Normalize this validated initial request
            // before challenging so login can resume it using Quarkus' redirect-location cookie.
            String location = context.normalizedPath();
            for (var parameter : context.request().formAttributes()) {
                location = OAuth2AuthorizationEndpointHandler.appendQueryParameter(
                        location, parameter.getKey(), parameter.getValue());
            }
            context.response().setStatusCode(HttpResponseStatus.SEE_OTHER.code())
                    .putHeader(HttpHeaders.LOCATION, location).end();
            return;
        }
        this.httpAuthenticator.sendChallenge(context).subscribe().with(challenged -> {
            if (!context.response().ended())
                context.response().end();
        }, context::fail);
    }

    void sendAuthorizationResponse(RoutingContext context, AuthorizationOutcome.CodeIssued issued) {
        String redirectUri = OAuth2AuthorizationEndpointHandler.appendQueryParameter(
                issued.redirectUri(),
                OAuth2ParameterNames.CODE,
                issued.code().getTokenValue());
        if (Arguments.hasText(issued.state())) {
            redirectUri = OAuth2AuthorizationEndpointHandler.appendQueryParameter(redirectUri, OAuth2ParameterNames.STATE,
                    issued.state());
        }
        context.response()
                .setStatusCode(HttpResponseStatus.FOUND.code())
                .putHeader(HttpHeaders.LOCATION, redirectUri)
                .end();
    }

    void sendErrorResponse(RoutingContext context, AuthorizationRequestException exception) {
        AuthorizationRedirect redirect = exception.getRedirect();
        if (redirect == null) {
            this.authenticationFailureHandler.onAuthenticationFailure(context, exception);
            return;
        }

        OAuth2Error error = exception.getError();
        String redirectUri = OAuth2AuthorizationEndpointHandler.appendQueryParameter(
                redirect.uri(), OAuth2ParameterNames.ERROR, error.getErrorCode());
        if (Arguments.hasText(error.getDescription())) {
            redirectUri = OAuth2AuthorizationEndpointHandler.appendQueryParameter(
                    redirectUri,
                    OAuth2ParameterNames.ERROR_DESCRIPTION,
                    error.getDescription());
        }
        if (Arguments.hasText(error.getUri())) {
            redirectUri = OAuth2AuthorizationEndpointHandler.appendQueryParameter(
                    redirectUri, OAuth2ParameterNames.ERROR_URI, error.getUri());
        }
        if (Arguments.hasText(redirect.state())) {
            redirectUri = OAuth2AuthorizationEndpointHandler.appendQueryParameter(redirectUri, OAuth2ParameterNames.STATE,
                    redirect.state());
        }
        context.response()
                .setStatusCode(HttpResponseStatus.FOUND.code())
                .putHeader(HttpHeaders.LOCATION, redirectUri)
                .end();
    }

    private void handleAuthenticationFailure(RoutingContext context, Throwable failure) {
        if (failure instanceof AuthorizationRequestException exception) {
            this.sendErrorResponse(context, exception);
        } else if (failure instanceof OAuth2AuthenticationException exception) {
            this.authenticationFailureHandler.onAuthenticationFailure(context, exception);
        } else {
            this.authenticationFailureHandler.onAuthenticationFailure(
                    context,
                    new OAuth2AuthenticationException(
                            new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), failure));
        }
    }

    private static String appendQueryParameter(String uri, String name, String value) {
        int fragmentIndex = uri.indexOf('#');
        String fragment = fragmentIndex >= 0 ? uri.substring(fragmentIndex) : "";
        String baseUri = fragmentIndex >= 0 ? uri.substring(0, fragmentIndex) : uri;
        String separator = baseUri.endsWith("?") || baseUri.endsWith("&")
                ? ""
                : baseUri.contains("?") ? "&" : "?";
        return baseUri + separator + OAuth2AuthorizationEndpointHandler.encode(name) + "="
                + OAuth2AuthorizationEndpointHandler.encode(value) + fragment;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8)
                .replace("+", "%20")
                .replace("*", "%2A")
                .replace("%7E", "~");
    }

    private static boolean isFormUrlEncoded(String contentType) {
        if (contentType == null) {
            return false;
        }
        int parametersIndex = contentType.indexOf(';');
        String mediaType = parametersIndex >= 0 ? contentType.substring(0, parametersIndex) : contentType;
        return FORM_URLENCODED.equalsIgnoreCase(mediaType.trim());
    }
}
