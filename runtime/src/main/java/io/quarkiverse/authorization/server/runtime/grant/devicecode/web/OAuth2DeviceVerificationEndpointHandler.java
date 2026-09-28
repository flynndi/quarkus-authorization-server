package io.quarkiverse.authorization.server.runtime.grant.devicecode.web;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceConsentSubmission;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceVerificationRequest;
import io.quarkiverse.authorization.server.grant.devicecode.OAuth2DeviceVerificationPage;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceConsentService;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceVerificationOutcome;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceVerificationService;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

/** Vert.x handler for device verification pages and authenticated user consent submissions. */
@Singleton
public final class OAuth2DeviceVerificationEndpointHandler implements Handler<RoutingContext> {

    private static final String FORM_URLENCODED = "application/x-www-form-urlencoded";
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final DeviceVerificationRequestParser verificationParser = new DeviceVerificationRequestParser();
    private final DeviceConsentSubmissionParser consentParser = new DeviceConsentSubmissionParser();
    private final DeviceVerificationService verificationService;
    private final DeviceConsentService consentService;
    private final OAuth2DeviceVerificationPage deviceVerificationPage;

    private final ProtocolExecutor executor;

    @Inject
    public OAuth2DeviceVerificationEndpointHandler(
            ProtocolExecutor executor,
            DeviceVerificationService verificationService,
            DeviceConsentService consentService,
            OAuth2DeviceVerificationPage deviceVerificationPage) {
        this.executor = executor;
        this.verificationService = verificationService;
        this.consentService = consentService;
        this.deviceVerificationPage = deviceVerificationPage;
    }

    @Override
    public void handle(RoutingContext context) {
        if (context.request().method() == HttpMethod.POST
                && !isFormUrlEncoded(context.request().getHeader(HttpHeaders.CONTENT_TYPE))) {
            context.response()
                    .setStatusCode(HttpResponseStatus.UNSUPPORTED_MEDIA_TYPE.code())
                    .end();
            return;
        }
        try {
            DeviceVerificationRequest verificationAuthentication = this.verificationParser.parse(context);
            if (verificationAuthentication != null) {
                this.executor
                        .execute(
                                context,
                                () -> this.verificationService.verify(verificationAuthentication))
                        .subscribe()
                        .with(
                                result -> handleResult(context, result),
                                failure -> handleFailure(context, failure));
                return;
            }

            DeviceConsentSubmission consentAuthentication = this.consentParser.parse(context);
            if (consentAuthentication != null) {
                this.executor
                        .execute(context, () -> this.consentService.consent(consentAuthentication))
                        .subscribe()
                        .with(
                                result -> handleResult(context, result),
                                failure -> handleFailure(context, failure));
                return;
            }

            if (context.request().method() == HttpMethod.GET) {
                this.deviceVerificationPage.displayVerification(context);
                return;
            }
            sendError(
                    context,
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_REQUEST,
                            "OAuth 2.0 Parameter: user_code",
                            ERROR_URI));
        } catch (OAuth2AuthenticationException exception) {
            sendError(context, exception.getError());
        }
    }

    private void handleResult(RoutingContext context, DeviceVerificationOutcome result) {
        if (result instanceof DeviceVerificationOutcome.ConfirmationRequired consent) {
            this.deviceVerificationPage.displayConfirmation(
                    context,
                    consent.clientId(),
                    consent.principal(),
                    consent.requestedScopes(),
                    consent.authorizedScopes(),
                    consent.userCode(),
                    consent.state());
            return;
        }
        if (result instanceof DeviceVerificationOutcome.Approved verification) {
            this.deviceVerificationPage.displaySuccess(context, verification.clientId());
            return;
        }
        handleFailure(context, new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR));
    }

    private void handleFailure(RoutingContext context, Throwable failure) {
        if (failure instanceof OAuth2AuthenticationException exception) {
            sendError(context, exception.getError());
            return;
        }
        sendError(context, new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
    }

    private void sendError(RoutingContext context, OAuth2Error error) {
        context.response()
                .setStatusCode(
                        OAuth2ErrorCodes.SERVER_ERROR.equals(error.getErrorCode())
                                ? HttpResponseStatus.INTERNAL_SERVER_ERROR.code()
                                : HttpResponseStatus.BAD_REQUEST.code());
        this.deviceVerificationPage.displayError(context, error);
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
