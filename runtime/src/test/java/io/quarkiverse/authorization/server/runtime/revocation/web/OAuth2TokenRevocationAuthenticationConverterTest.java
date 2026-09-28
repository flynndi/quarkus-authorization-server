package io.quarkiverse.authorization.server.runtime.revocation.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.revocation.authentication.OAuth2TokenRevocationAuthenticationToken;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;

class OAuth2TokenRevocationAuthenticationConverterTest {

    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("revoking-client"))
            .build();

    private final OAuth2TokenRevocationAuthenticationConverter converter = new OAuth2TokenRevocationAuthenticationConverter();

    @Test
    void convertsTokenAndHint() {
        MultiMap parameters = MultiMap.caseInsensitiveMultiMap()
                .add(OAuth2ParameterNames.TOKEN, "access-token")
                .add(OAuth2ParameterNames.TOKEN_TYPE_HINT, "access_token")
                .add("ignored", "value");

        OAuth2TokenRevocationAuthenticationToken authentication = this.converter.convert(context(parameters));

        assertSame(CLIENT_PRINCIPAL, authentication.getPrincipal());
        assertEquals("access-token", authentication.getToken());
        assertEquals("access_token", authentication.getTokenTypeHint());
        assertFalse(authentication.isAuthenticated());
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

        OAuth2TokenRevocationAuthenticationToken authentication = this.converter.convert(context(
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
        assertEquals("OAuth 2.0 Token Revocation Parameter: " + parameter,
                exception.getError().getDescription());
        assertEquals("https://datatracker.ietf.org/doc/html/rfc7009#section-2.1",
                exception.getError().getUri());
    }

    private static RoutingContext context(MultiMap parameters) {
        return context(parameters, new QuarkusHttpUser(CLIENT_PRINCIPAL));
    }

    private static RoutingContext context(MultiMap parameters, User user) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                OAuth2TokenRevocationAuthenticationConverterTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, arguments) -> {
                    if ("formAttributes".equals(method.getName())) {
                        return parameters;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                OAuth2TokenRevocationAuthenticationConverterTest.class.getClassLoader(),
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
