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
package io.quarkiverse.authorization.server.runtime.introspection.web;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.introspection.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
import io.quarkus.vertx.VertxContextSupport;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

/**
 * Vert.x handler that dispatches token introspection for an authenticated client and writes token metadata.
 */
@Singleton
public final class OAuth2TokenIntrospectionEndpointHandler implements Handler<RoutingContext> {

    private static final String FORM_URLENCODED = "application/x-www-form-urlencoded";

    private final OAuth2TokenIntrospectionAuthenticationConverter authenticationConverter = new OAuth2TokenIntrospectionAuthenticationConverter();
    private final Instance<OAuth2TokenIntrospectionAuthenticationProvider> authenticationProvider;
    private final OAuth2TokenIntrospectionHttpMessageConverter tokenIntrospectionResponseConverter;
    private final OAuth2ErrorAuthenticationFailureHandler authenticationFailureHandler;

    @Inject
    public OAuth2TokenIntrospectionEndpointHandler(
            Instance<OAuth2TokenIntrospectionAuthenticationProvider> authenticationProvider,
            OAuth2TokenIntrospectionHttpMessageConverter tokenIntrospectionResponseConverter,
            OAuth2ErrorHttpMessageConverter errorResponseConverter) {
        this.authenticationProvider = authenticationProvider;
        this.tokenIntrospectionResponseConverter = tokenIntrospectionResponseConverter;
        this.authenticationFailureHandler = new OAuth2ErrorAuthenticationFailureHandler(errorResponseConverter);
    }

    @Override
    public void handle(RoutingContext context) {
        if (!isFormUrlEncoded(context.request().getHeader(HttpHeaderNames.CONTENT_TYPE))) {
            context.response().setStatusCode(HttpResponseStatus.UNSUPPORTED_MEDIA_TYPE.code()).end();
            return;
        }
        context.response().putHeader(HttpHeaderNames.CACHE_CONTROL, "no-store")
                .putHeader(HttpHeaderNames.PRAGMA, "no-cache");

        try {
            var authentication = this.authenticationConverter.convert(context);
            VertxContextSupport.executeBlocking(() -> this.authenticationProvider.get().authenticate(authentication))
                    .subscribe().with(
                            result -> {
                                try {
                                    this.tokenIntrospectionResponseConverter.write(
                                            result.getTokenClaims(), context.response());
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
