/*
 * Copyright 2020-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.quarkiverse.authorization.server.runtime.revocation.web;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.revocation.authentication.OAuth2TokenRevocationAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

/**
 * Vert.x handler that processes token revocation for an authenticated OAuth client.
 */
@Singleton
public final class OAuth2TokenRevocationEndpointHandler implements Handler<RoutingContext> {

    private static final String FORM_URLENCODED = "application/x-www-form-urlencoded";

    private final OAuth2TokenRevocationAuthenticationConverter authenticationConverter = new OAuth2TokenRevocationAuthenticationConverter();
    private final Instance<OAuth2TokenRevocationAuthenticationProvider> authenticationProvider;
    private final OAuth2ErrorAuthenticationFailureHandler authenticationFailureHandler;
    private final ProtocolExecutor executor;

    @Inject
    public OAuth2TokenRevocationEndpointHandler(
            Instance<OAuth2TokenRevocationAuthenticationProvider> authenticationProvider,
            OAuth2ErrorHttpMessageConverter errorResponseConverter, ProtocolExecutor executor) {
        this.authenticationProvider = authenticationProvider;
        this.authenticationFailureHandler = new OAuth2ErrorAuthenticationFailureHandler(errorResponseConverter);
        this.executor = executor;
    }

    @Override
    public void handle(RoutingContext context) {
        if (!isFormUrlEncoded(context.request().getHeader(HttpHeaderNames.CONTENT_TYPE))) {
            context.response().setStatusCode(HttpResponseStatus.UNSUPPORTED_MEDIA_TYPE.code()).end();
            return;
        }

        try {
            var authentication = this.authenticationConverter.convert(context);
            this.executor.execute(context, () -> this.authenticationProvider.get().authenticate(authentication))
                    .subscribe().with(
                            result -> context.response().setStatusCode(HttpResponseStatus.OK.code()).end(),
                            failure -> sendError(context, failure));
        } catch (RuntimeException failure) {
            sendError(context, failure);
        }
    }

    private void sendError(RoutingContext context, Throwable failure) {
        OAuth2AuthenticationException exception = failure instanceof OAuth2AuthenticationException oauth2Exception
                ? oauth2Exception
                : new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), failure);
        this.authenticationFailureHandler.onAuthenticationFailure(context, exception);
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
