package io.quarkiverse.authorization.server.runtime.introspection.web;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.introspection.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;

class OAuth2TokenIntrospectionAuthenticationConverterTest {

    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("introspecting-client"))
            .build();

    private final OAuth2TokenIntrospectionAuthenticationConverter converter = new OAuth2TokenIntrospectionAuthenticationConverter();

    @Test
    void convertsTokenHintAndAdditionalParameters() {
        MultiMap parameters = MultiMap.caseInsensitiveMultiMap()
                .add(OAuth2ParameterNames.TOKEN, "access-token")
                .add(OAuth2ParameterNames.TOKEN_TYPE_HINT, "access_token")
                .add("custom", "value")
                .add("resource", "one")
                .add("resource", "two");

        OAuth2TokenIntrospectionAuthenticationToken authentication = this.converter.convert(context(parameters));

        assertSame(CLIENT_PRINCIPAL, authentication.getPrincipal());
        assertEquals("access-token", authentication.getToken());
        assertEquals("access_token", authentication.getTokenTypeHint());
        assertEquals("value", authentication.getAdditionalParameters().get("custom"));
        assertArrayEquals(new String[] { "one", "two" },
                (String[]) authentication.getAdditionalParameters().get("resource"));
        assertFalse(authentication.isAuthenticated());
        assertFalse(authentication.getTokenClaims().isActive());
    }

    @Test
    void rejectsMissingBlankOrRepeatedToken() {
        assertInvalid(OAuth2ParameterNames.TOKEN, MultiMap.caseInsensitiveMultiMap());
        assertInvalid(OAuth2ParameterNames.TOKEN, MultiMap.caseInsensitiveMultiMap()
                .add(OAuth2ParameterNames.TOKEN, " "));
        assertInvalid(OAuth2ParameterNames.TOKEN, MultiMap.caseInsensitiveMultiMap()
                .add(OAuth2ParameterNames.TOKEN, "one")
                .add(OAuth2ParameterNames.TOKEN, "two"));
    }

    @Test
    void rejectsRepeatedNonBlankHintButIgnoresBlankFirstValue() {
        assertInvalid(OAuth2ParameterNames.TOKEN_TYPE_HINT, MultiMap.caseInsensitiveMultiMap()
                .add(OAuth2ParameterNames.TOKEN, "token")
                .add(OAuth2ParameterNames.TOKEN_TYPE_HINT, "access_token")
                .add(OAuth2ParameterNames.TOKEN_TYPE_HINT, "refresh_token"));

        OAuth2TokenIntrospectionAuthenticationToken authentication = this.converter.convert(context(
                MultiMap.caseInsensitiveMultiMap()
                        .add(OAuth2ParameterNames.TOKEN, "token")
                        .add(OAuth2ParameterNames.TOKEN_TYPE_HINT, "")
                        .add(OAuth2ParameterNames.TOKEN_TYPE_HINT, "access_token")));
        assertEquals("", authentication.getTokenTypeHint());
    }

    @Test
    void requiresAuthenticatedHttpPrincipal() {
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> this.converter.convert(context(MultiMap.caseInsensitiveMultiMap()
                        .add(OAuth2ParameterNames.TOKEN, "token"), null)));
        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, exception.getError().getErrorCode());
    }

    private void assertInvalid(String parameter, MultiMap parameters) {
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> this.converter.convert(context(parameters)));
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals("OAuth 2.0 Token Introspection Parameter: " + parameter,
                exception.getError().getDescription());
        assertEquals("https://datatracker.ietf.org/doc/html/rfc7662#section-2.1",
                exception.getError().getUri());
    }

    private static RoutingContext context(MultiMap parameters) {
        return context(parameters, new QuarkusHttpUser(CLIENT_PRINCIPAL));
    }

    private static RoutingContext context(MultiMap parameters, User user) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                OAuth2TokenIntrospectionAuthenticationConverterTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, arguments) -> {
                    if ("formAttributes".equals(method.getName())) {
                        return parameters;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                OAuth2TokenIntrospectionAuthenticationConverterTest.class.getClassLoader(),
                new Class<?>[] { RoutingContext.class },
                (proxy, method, arguments) -> {
                    if ("request".equals(method.getName())) {
                        return request;
                    }
                    if ("user".equals(method.getName())) {
                        return user;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
    }
}
