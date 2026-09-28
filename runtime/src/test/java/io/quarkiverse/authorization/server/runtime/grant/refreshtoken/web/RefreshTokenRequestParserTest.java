package io.quarkiverse.authorization.server.runtime.grant.refreshtoken.web;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.grant.refreshtoken.RefreshTokenRequest;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;

class RefreshTokenRequestParserTest {

    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("messaging-client"))
            .build();

    private final RefreshTokenRequestParser converter = new RefreshTokenRequestParser();

    @Test
    void convertsRefreshTokenGrantRequest() {
        MultiMap parameters = validParameters()
                .add("scope", "message.read message.write")
                .add("resource", "messages")
                .add("audience", "one")
                .add("audience", "two");

        RefreshTokenRequest authentication = this.converter.parse(context(parameters));

        assertSame(CLIENT_PRINCIPAL, authentication.getClientPrincipal());
        assertEquals("refresh-token", authentication.getRefreshToken());
        assertEquals(Set.of("message.read", "message.write"), authentication.getScopes());
        assertEquals("messages", authentication.getAdditionalParameters().get("resource"));
        assertArrayEquals(
                new String[] { "one", "two" },
                (String[]) authentication.getAdditionalParameters().get("audience"));
    }

    @Test
    void treatsMissingOrBlankScopeAsUnspecified() {
        assertEquals(Set.of(), this.converter.parse(context(validParameters())).getScopes());
        assertEquals(
                Set.of(),
                this.converter.parse(context(validParameters().add("scope", " "))).getScopes());
    }

    @Test
    void returnsNullForAnotherGrantType() {
        assertNull(this.converter.parse(context(validParameters().set("grant_type", "password"))));
    }

    @Test
    void rejectsMissingRepeatedAndBlankRefreshToken() {
        assertInvalidParameter(validParameters().remove("refresh_token"), "refresh_token");
        assertInvalidParameter(
                validParameters().add("refresh_token", "another-token"), "refresh_token");
        assertInvalidParameter(validParameters().set("refresh_token", " "), "refresh_token");
    }

    @Test
    void rejectsRepeatedNonBlankScope() {
        assertInvalidParameter(
                validParameters().add("scope", "message.read").add("scope", "message.write"),
                "scope");
    }

    @Test
    void requiresAuthenticatedClientPrincipal() {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.parse(context(validParameters(), null)));

        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, exception.getError().getErrorCode());
    }

    private void assertInvalidParameter(MultiMap parameters, String parameterName) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.parse(context(parameters)));
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals(
                "OAuth 2.0 Parameter: " + parameterName, exception.getError().getDescription());
    }

    private static MultiMap validParameters() {
        return MultiMap.caseInsensitiveMultiMap()
                .add("grant_type", "refresh_token")
                .add("refresh_token", "refresh-token");
    }

    private static RoutingContext context(MultiMap parameters) {
        return context(parameters, new QuarkusHttpUser(CLIENT_PRINCIPAL));
    }

    private static RoutingContext context(MultiMap parameters, User user) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                RefreshTokenRequestParserTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, arguments) -> {
                    if ("formAttributes".equals(method.getName())) {
                        return parameters;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                RefreshTokenRequestParserTest.class.getClassLoader(),
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
