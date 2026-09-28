package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.client.InMemoryRegisteredClientRepository;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.config.TestOidcConfig;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationConsentProcessor;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationOutcome;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationRedirect;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationRequestChecks;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationRequestException;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationRequestProcessor;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.DefaultAuthorizationCodeGenerator;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.DefaultAuthorizationConsentPolicy;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;

class OAuth2AuthorizationEndpointHandlerTest {

    private static final TestOidcConfig OIDC_CONFIG = new TestOidcConfig(false, false);

    private static final SecurityIdentity PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("resource-owner"))
            .build();
    private static final AuthorizationServerSettings AUTHORIZATION_SERVER_SETTINGS = AuthorizationServerSettings.builder()
            .issuer("https://issuer.example.com").build();

    private final InMemoryRegisteredClientRepository registeredClientRepository = new InMemoryRegisteredClientRepository(
            RegisteredClient.withId("messaging-client")
                    .clientId("messaging-client")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("https://client.example.com/callback")
                    .scope("message.read")
                    .build());
    private final InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();
    private final InMemoryOAuth2AuthorizationConsentService authorizationConsentService = new InMemoryOAuth2AuthorizationConsentService();
    private final OAuth2AuthorizationEndpointHandler handler = new OAuth2AuthorizationEndpointHandler(
            new AuthorizationRequestProcessor(
                    this.registeredClientRepository,
                    this.authorizationService,
                    this.authorizationConsentService,
                    new DefaultAuthorizationServerContext(AUTHORIZATION_SERVER_SETTINGS),
                    OIDC_CONFIG,
                    java.util.List.of(new AuthorizationRequestChecks()),
                    new DefaultAuthorizationConsentPolicy(),
                    new DefaultAuthorizationCodeGenerator()),
            new AuthorizationConsentProcessor(
                    this.registeredClientRepository,
                    this.authorizationService,
                    this.authorizationConsentService,
                    new DefaultAuthorizationServerContext(AUTHORIZATION_SERVER_SETTINGS),
                    new DefaultAuthorizationCodeGenerator(),
                    java.util.List.of(context -> {
                    })),
            new DefaultConsentPage(),
            null,
            new OAuth2ErrorHttpMessageConverter(new ObjectMapper()));

    @Test
    void redirectsSuccessfulAuthorizationResponse() {
        ResponseCapture capture = new ResponseCapture();
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                "authorization-code", Instant.now(), Instant.now().plusSeconds(300));
        AuthorizationOutcome.CodeIssued authentication = new AuthorizationOutcome.CodeIssued(
                authorizationCode,
                "https://client.example.com/callback?tenant=internal",
                "state value",
                Set.of("message.read"));

        this.handler.sendAuthorizationResponse(context(capture), authentication);

        assertEquals(302, capture.statusCode);
        assertEquals(
                "https://client.example.com/callback?tenant=internal&code=authorization-code&state=state%20value",
                capture.headers.get(HttpHeaders.LOCATION.toString()));
    }

    @Test
    void redirectsErrorOnlyWhenExceptionContainsValidatedAuthorizationRequest() {
        ResponseCapture capture = new ResponseCapture();
        AuthorizationRedirect redirect = new AuthorizationRedirect("https://client.example.com/callback", "state value");
        this.handler.sendErrorResponse(
                context(capture),
                new AuthorizationRequestException(
                        new OAuth2Error(
                                OAuth2ErrorCodes.INVALID_SCOPE,
                                "Invalid scope",
                                "https://example.com/error"),
                        redirect));

        assertEquals(302, capture.statusCode);
        assertEquals(
                "https://client.example.com/callback?error=invalid_scope"
                        + "&error_description=Invalid%20scope&error_uri=https%3A%2F%2Fexample.com%2Ferror&state=state%20value",
                capture.headers.get(HttpHeaders.LOCATION.toString()));
    }

    @Test
    void writesJsonErrorWhenRedirectUriHasNotBeenValidated() {
        ResponseCapture capture = new ResponseCapture();

        this.handler.sendErrorResponse(
                context(capture),
                new AuthorizationRequestException(
                        new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid request", null),
                        null));

        assertEquals(400, capture.statusCode);
        assertEquals(
                "application/json;charset=UTF-8",
                capture.headers.get(HttpHeaders.CONTENT_TYPE.toString()));
        assertEquals(
                "{\"error\":\"invalid_request\",\"error_description\":\"Invalid request\"}",
                capture.body);
        assertFalse(capture.headers.containsKey(HttpHeaders.LOCATION.toString()));
    }

    private static RoutingContext context(ResponseCapture capture) {
        HttpServerResponse response = (HttpServerResponse) Proxy.newProxyInstance(
                OAuth2AuthorizationEndpointHandlerTest.class.getClassLoader(),
                new Class<?>[] { HttpServerResponse.class },
                (proxy, method, arguments) -> {
                    switch (method.getName()) {
                        case "setStatusCode" ->
                            capture.statusCode = (int) arguments[0];
                        case "putHeader" ->
                            capture.headers.put(
                                    arguments[0].toString(),
                                    arguments[1].toString());
                        case "end" -> {
                            if (arguments != null && arguments.length == 1) {
                                capture.body = arguments[0].toString();
                            }
                            return null;
                        }
                        default ->
                            throw new UnsupportedOperationException(
                                    method.toString());
                    }
                    return proxy;
                });
        return (RoutingContext) Proxy.newProxyInstance(
                OAuth2AuthorizationEndpointHandlerTest.class.getClassLoader(),
                new Class<?>[] { RoutingContext.class },
                (proxy, method, arguments) -> {
                    if ("response".equals(method.getName())) {
                        return response;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
    }

    private static final class ResponseCapture {

        private int statusCode;
        private final Map<String, String> headers = new LinkedHashMap<>();
        private String body;
    }
}
