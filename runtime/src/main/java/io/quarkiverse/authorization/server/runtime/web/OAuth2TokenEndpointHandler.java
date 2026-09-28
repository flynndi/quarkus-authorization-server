package io.quarkiverse.authorization.server.runtime.web;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofRequest;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
import io.quarkiverse.authorization.server.web.TokenGrantHandler;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpHeaders;
import io.vertx.ext.web.RoutingContext;

/** Vert.x token endpoint that dispatches grant requests to CDI TokenGrantHandler implementations. */
@Singleton
public final class OAuth2TokenEndpointHandler implements Handler<RoutingContext> {

    private static final String FORM_URLENCODED = "application/x-www-form-urlencoded";
    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final OAuth2ErrorAuthenticationFailureHandler authenticationFailureHandler;
    private final Map<String, TokenGrantHandler> authorizationGrantHandlers;
    private final TokenResponseWriter tokenResponseWriter;

    @Inject
    public OAuth2TokenEndpointHandler(
            Instance<TokenGrantHandler> authorizationGrantHandlers,
            TokenResponseWriter tokenResponseWriter,
            OAuth2ErrorHttpMessageConverter errorResponseConverter) {
        // The recorder creates this handler at startup; CDI iteration order must not select a grant
        // implementation.
        Map<String, TokenGrantHandler> handlers = new HashMap<>();
        for (TokenGrantHandler handler : authorizationGrantHandlers) {
            String grantType = handler.getGrantType().getValue();
            TokenGrantHandler previous = handlers.putIfAbsent(grantType, handler);
            if (previous != null) {
                throw new IllegalStateException(
                        "Duplicate OAuth2 authorization grant handlers for grant_type '"
                                + grantType
                                + "': "
                                + previous.getClass().getName()
                                + " and "
                                + handler.getClass().getName());
            }
        }
        this.authorizationGrantHandlers = Map.copyOf(handlers);
        this.tokenResponseWriter = tokenResponseWriter;
        this.authenticationFailureHandler = new OAuth2ErrorAuthenticationFailureHandler(errorResponseConverter);
    }

    @Override
    public void handle(RoutingContext context) {
        if (!isFormUrlEncoded(context.request().getHeader(HttpHeaders.CONTENT_TYPE))) {
            context.response()
                    .setStatusCode(HttpResponseStatus.UNSUPPORTED_MEDIA_TYPE.code())
                    .end();
            return;
        }

        try {
            List<String> grantTypes = context.request().formAttributes().getAll(OAuth2ParameterNames.GRANT_TYPE);
            if (grantTypes.size() != 1 || grantTypes.get(0).isBlank()) {
                throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.GRANT_TYPE);
            }

            if (context.request().headers().contains(DPoPProofRequest.HEADER_NAME)
                    && !java.util.Set.of(
                            AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
                            AuthorizationGrantType.REFRESH_TOKEN.getValue(),
                            AuthorizationGrantType.CLIENT_CREDENTIALS.getValue(),
                            AuthorizationGrantType.DEVICE_CODE.getValue(),
                            AuthorizationGrantType.TOKEN_EXCHANGE.getValue())
                            .contains(grantTypes.get(0))) {
                throwError(OAuth2ErrorCodes.INVALID_DPOP_PROOF, DPoPProofRequest.HEADER_NAME);
            }
            TokenGrantHandler authorizationGrantHandler = this.authorizationGrantHandlers.get(grantTypes.get(0));
            if (authorizationGrantHandler == null) {
                throwError(
                        OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, OAuth2ParameterNames.GRANT_TYPE);
            }

            authorizationGrantHandler
                    .handle(context)
                    .onItem()
                    .ifNull()
                    .failWith(
                            () -> new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR))
                    .subscribe()
                    .with(
                            result -> this.tokenResponseWriter.write(context, result),
                            failure -> this.authenticationFailureHandler.onAuthenticationFailure(
                                    context,
                                    failure instanceof OAuth2AuthenticationException oauth2AuthenticationException
                                            ? oauth2AuthenticationException
                                            : new OAuth2AuthenticationException(
                                                    new OAuth2Error(
                                                            OAuth2ErrorCodes.SERVER_ERROR),
                                                    failure)));
        } catch (OAuth2AuthenticationException exception) {
            this.authenticationFailureHandler.onAuthenticationFailure(context, exception);
        }
    }

    private static boolean isFormUrlEncoded(String contentType) {
        if (contentType == null) {
            return false;
        }
        int parametersIndex = contentType.indexOf(';');
        String mediaType = parametersIndex >= 0 ? contentType.substring(0, parametersIndex) : contentType;
        return FORM_URLENCODED.equalsIgnoreCase(mediaType.trim());
    }

    private static void throwError(String errorCode, String parameterName) {
        throw new OAuth2AuthenticationException(
                new OAuth2Error(
                        errorCode, "OAuth 2.0 Parameter: " + parameterName, DEFAULT_ERROR_URI));
    }
}
