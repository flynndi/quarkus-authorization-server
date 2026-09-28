package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeExchangeRequest;
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

class AuthorizationCodeExchangeRequestParserTest {

    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("messaging-client"))
            .build();

    private final AuthorizationCodeExchangeRequestParser converter = new AuthorizationCodeExchangeRequestParser();

    @Test
    void convertsAuthorizationCodeGrantRequest() {
        MultiMap parameters = validParameters()
                .add("redirect_uri", "https://client.example.com/callback")
                .add("code_verifier", "verifier")
                .add("resource", "messages");

        AuthorizationCodeExchangeRequest authentication = this.converter.parse(context(parameters));

        assertSame(CLIENT_PRINCIPAL, authentication.getClientPrincipal());
        assertEquals("authorization-code", authentication.getCode());
        assertEquals("https://client.example.com/callback", authentication.getRedirectUri());
        assertEquals(
                Map.of("code_verifier", "verifier", "resource", "messages"),
                authentication.getAdditionalParameters());
    }

    @Test
    void returnsNullForAnotherGrantType() {
        assertNull(this.converter.parse(context(validParameters().set("grant_type", "password"))));
    }

    @Test
    void rejectsMissingRepeatedAndBlankCode() {
        assertInvalidParameter(validParameters().remove("code"), "code");
        assertInvalidParameter(validParameters().add("code", "another-code"), "code");
        assertInvalidParameter(validParameters().set("code", " "), "code");
    }

    @Test
    void rejectsRepeatedRedirectUri() {
        assertInvalidParameter(
                validParameters()
                        .add("redirect_uri", "https://client.example.com/callback")
                        .add("redirect_uri", "https://client.example.com/other"),
                "redirect_uri");
    }

    @Test
    void rejectsRepeatedOrBlankVerifier() {
        assertInvalidParameter(
                validParameters().add("code_verifier", "one").add("code_verifier", "two"),
                "code_verifier");
        assertInvalidParameter(validParameters().add("code_verifier", " "), "code_verifier");
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
                .add("grant_type", "authorization_code")
                .add("code", "authorization-code");
    }

    private static RoutingContext context(MultiMap parameters) {
        return context(parameters, new QuarkusHttpUser(CLIENT_PRINCIPAL));
    }

    private static RoutingContext context(MultiMap parameters, User user) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                AuthorizationCodeExchangeRequestParserTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, arguments) -> {
                    if ("formAttributes".equals(method.getName())) {
                        return parameters;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                AuthorizationCodeExchangeRequestParserTest.class.getClassLoader(),
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
