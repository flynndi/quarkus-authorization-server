package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequest;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationRequestException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;

class AuthorizationRequestParserTest {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
    private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";
    private static final SecurityIdentity PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("resource-owner"))
            .build();

    private final AuthorizationRequestParser converter = new AuthorizationRequestParser();

    @Test
    void convertsAuthorizationCodeRequest() {
        MultiMap parameters = validParameters()
                .add("redirect_uri", "https://client.example.com/callback")
                .add("scope", "message.read message.write")
                .add("state", "state")
                .add("code_challenge", "challenge")
                .add("code_challenge_method", "S256")
                .add("tenant", "internal")
                .add("resource", "one")
                .add("resource", "two");

        AuthorizationRequest authentication = this.converter.parse(
                context(HttpMethod.GET, parameters, new QuarkusHttpUser(PRINCIPAL)));

        assertEquals(
                "https://issuer.example.com/oauth2/authorize",
                authentication.getAuthorizationUri());
        assertEquals("messaging-client", authentication.getClientId());
        assertSame(PRINCIPAL, authentication.getPrincipal());
        assertEquals("https://client.example.com/callback", authentication.getRedirectUri());
        assertEquals("state", authentication.getState());
        assertEquals(Set.of("message.read", "message.write"), authentication.getScopes());
        assertEquals("challenge", authentication.getAdditionalParameters().get("code_challenge"));
        assertEquals("S256", authentication.getAdditionalParameters().get("code_challenge_method"));
        assertEquals("internal", authentication.getAdditionalParameters().get("tenant"));
        assertArrayEquals(
                new String[] { "one", "two" },
                (String[]) authentication.getAdditionalParameters().get("resource"));
        assertFalse(authentication.getAdditionalParameters().containsKey("client_id"));
    }

    @Test
    void doesNotConvertPlainOAuthPostOrConsentRequests() {
        assertNull(
                this.converter.parse(
                        context(
                                HttpMethod.POST,
                                validParameters(),
                                new QuarkusHttpUser(PRINCIPAL))));
        assertNull(
                this.converter.parse(
                        context(
                                HttpMethod.POST,
                                validParameters().remove("response_type").add("scope", "openid"),
                                new QuarkusHttpUser(PRINCIPAL))));
    }

    @Test
    void convertsOpenidPostAuthorizationRequest() {
        var authentication = this.converter.parse(
                context(
                        HttpMethod.POST,
                        validParameters()
                                .add("scope", "openid profile")
                                .add("nonce", "post-nonce"),
                        new QuarkusHttpUser(PRINCIPAL)));
        assertEquals(Set.of("openid", "profile"), authentication.getScopes());
        assertEquals("post-nonce", authentication.getAdditionalParameters().get("nonce"));
        assertSame(PRINCIPAL, authentication.getPrincipal());
    }

    @Test
    void usesAnonymousPrincipalWhenHttpSecurityHasNotAuthenticatedRequest() {
        AuthorizationRequest authentication = this.converter.parse(context(HttpMethod.GET, validParameters(), null));

        assertTrue(authentication.getPrincipal().isAnonymous());
        assertEquals("anonymousUser", authentication.getPrincipal().getPrincipal().getName());
    }

    @Test
    void rejectsInvalidResponseType() {
        assertInvalidParameter(
                validParameters().remove("response_type"),
                "response_type",
                OAuth2ErrorCodes.INVALID_REQUEST,
                ERROR_URI);
        assertInvalidParameter(
                validParameters().add("response_type", "code"),
                "response_type",
                OAuth2ErrorCodes.INVALID_REQUEST,
                ERROR_URI);
        assertInvalidParameter(
                validParameters().set("response_type", "token"),
                "response_type",
                OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE,
                ERROR_URI);
    }

    @Test
    void rejectsInvalidClientIdAndRepeatedPkceParameters() {
        assertInvalidParameter(
                validParameters().remove("client_id"),
                "client_id",
                OAuth2ErrorCodes.INVALID_REQUEST,
                ERROR_URI);
        assertInvalidParameter(
                validParameters().add("code_challenge", "one").add("code_challenge", "two"),
                "code_challenge",
                OAuth2ErrorCodes.INVALID_REQUEST,
                PKCE_ERROR_URI);
        assertInvalidParameter(
                validParameters()
                        .add("code_challenge_method", "S256")
                        .add("code_challenge_method", "plain"),
                "code_challenge_method",
                OAuth2ErrorCodes.INVALID_REQUEST,
                PKCE_ERROR_URI);
    }

    private void assertInvalidParameter(
            MultiMap parameters, String parameterName, String errorCode, String errorUri) {
        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> this.converter.parse(
                        context(
                                HttpMethod.GET,
                                parameters,
                                new QuarkusHttpUser(PRINCIPAL))));

        assertEquals(errorCode, exception.getError().getErrorCode());
        assertEquals(
                "OAuth 2.0 Parameter: " + parameterName, exception.getError().getDescription());
        assertEquals(errorUri, exception.getError().getUri());
        assertNull(exception.getRedirect());
    }

    private static MultiMap validParameters() {
        return MultiMap.caseInsensitiveMultiMap()
                .add("response_type", "code")
                .add("client_id", "messaging-client");
    }

    static RoutingContext context(HttpMethod method, MultiMap parameters, User user) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                AuthorizationRequestParserTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, invokedMethod, arguments) -> switch (invokedMethod.getName()) {
                    case "method" -> method;
                    case "absoluteURI" ->
                        "https://issuer.example.com/oauth2/authorize?request=true";
                    case "formAttributes" -> parameters;
                    default ->
                        throw new UnsupportedOperationException(
                                invokedMethod.toString());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                AuthorizationRequestParserTest.class.getClassLoader(),
                new Class<?>[] { RoutingContext.class },
                (proxy, invokedMethod, arguments) -> switch (invokedMethod.getName()) {
                    case "request" -> request;
                    case "queryParams" -> parameters;
                    case "user" -> user;
                    default ->
                        throw new UnsupportedOperationException(
                                invokedMethod.toString());
                });
    }
}
