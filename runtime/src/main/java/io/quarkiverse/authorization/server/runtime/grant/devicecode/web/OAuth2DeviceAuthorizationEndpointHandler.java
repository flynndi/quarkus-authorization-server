package io.quarkiverse.authorization.server.runtime.grant.devicecode.web;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2DeviceAuthorizationResponse;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceAuthorizationService;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceCodesIssued;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2DeviceAuthorizationResponseHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

/** Vert.x handler that issues device authorization codes for an authenticated OAuth client. */
@Singleton
public final class OAuth2DeviceAuthorizationEndpointHandler implements Handler<RoutingContext> {

    private static final String FORM_URLENCODED = "application/x-www-form-urlencoded";

    private final DeviceAuthorizationRequestParser requestParser = new DeviceAuthorizationRequestParser();
    private final DeviceAuthorizationService authorizationService;
    private final AuthorizationServerContext authorizationServerContext;
    private final OAuth2DeviceAuthorizationResponseHttpMessageConverter responseConverter;
    private final OAuth2ErrorAuthenticationFailureHandler authenticationFailureHandler;

    private final ProtocolExecutor executor;

    @Inject
    public OAuth2DeviceAuthorizationEndpointHandler(
            ProtocolExecutor executor,
            DeviceAuthorizationService authorizationService,
            AuthorizationServerContext authorizationServerContext,
            OAuth2DeviceAuthorizationResponseHttpMessageConverter responseConverter,
            OAuth2ErrorHttpMessageConverter errorResponseConverter) {
        this.executor = executor;
        this.authorizationService = authorizationService;
        this.authorizationServerContext = authorizationServerContext;
        this.responseConverter = responseConverter;
        this.authenticationFailureHandler = new OAuth2ErrorAuthenticationFailureHandler(errorResponseConverter);
    }

    @Override
    public void handle(RoutingContext context) {
        if (!isFormUrlEncoded(context.request().getHeader(HttpHeaderNames.CONTENT_TYPE))) {
            context.response()
                    .setStatusCode(HttpResponseStatus.UNSUPPORTED_MEDIA_TYPE.code())
                    .end();
            return;
        }

        try {
            var authentication = this.requestParser.parse(context);
            this.executor
                    .execute(context, () -> this.authorizationService.authorize(authentication))
                    .subscribe()
                    .with(
                            result -> sendDeviceAuthorizationResponse(context, result),
                            failure -> sendError(context, failure));
        } catch (RuntimeException failure) {
            sendError(context, failure);
        }
    }

    private void sendDeviceAuthorizationResponse(RoutingContext context, DeviceCodesIssued result) {
        try {
            String verificationUri = verificationUri(context);
            String verificationUriComplete = verificationUri
                    + "?"
                    + OAuth2ParameterNames.USER_CODE
                    + "="
                    + encode(result.userCode().getTokenValue());
            OAuth2DeviceAuthorizationResponse response = OAuth2DeviceAuthorizationResponse
                    .with(result.deviceCode(), result.userCode())
                    .verificationUri(verificationUri)
                    .verificationUriComplete(verificationUriComplete)
                    .build();
            this.responseConverter.write(response, context.response());
        } catch (RuntimeException failure) {
            sendError(context, failure);
        }
    }

    private String verificationUri(RoutingContext context) {
        String issuer = this.authorizationServerContext.getIssuer();
        if (issuer != null && !issuer.isBlank()) {
            return join(issuer,
                    this.authorizationServerContext.getAuthorizationServerSettings().getDeviceVerificationEndpoint());
        }
        String absoluteUri = context.request().absoluteURI();
        int schemeEnd = absoluteUri.indexOf("://");
        int pathStart = schemeEnd >= 0 ? absoluteUri.indexOf('/', schemeEnd + 3) : -1;
        String origin = pathStart >= 0 ? absoluteUri.substring(0, pathStart) : absoluteUri;
        return join(origin, this.authorizationServerContext.getAuthorizationServerSettings().getDeviceVerificationEndpoint());
    }

    private void sendError(RoutingContext context, Throwable failure) {
        OAuth2AuthenticationException exception = failure instanceof OAuth2AuthenticationException oauth2Exception
                ? oauth2Exception
                : new OAuth2AuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), failure);
        this.authenticationFailureHandler.onAuthenticationFailure(context, exception);
    }

    private static String join(String base, String path) {
        if (base.endsWith("/") && path.startsWith("/")) {
            return base.substring(0, base.length() - 1) + path;
        }
        if (!base.endsWith("/") && !path.startsWith("/")) {
            return base + "/" + path;
        }
        return base + path;
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
