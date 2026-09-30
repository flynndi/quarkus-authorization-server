package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.ClientSecretVerifier;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.grant.TokenGrantRequest;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeExchangeRequest;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceCodeExchangeRequest;
import io.quarkiverse.authorization.server.grant.password.PasswordGrantRequest;
import io.quarkiverse.authorization.server.grant.refreshtoken.RefreshTokenRequest;
import io.quarkiverse.authorization.server.grant.tokenexchange.TokenExchangeRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.runtime.client.authentication.JwtClientAssertionAuthenticationRequest;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.client.authentication.X509ClientCertificateAuthenticationRequest;
import io.quarkiverse.authorization.server.runtime.security.OAuth2AccessTokenAuthenticationRequest;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkiverse.authorization.server.web.TokenGrantHandler;
import io.quarkus.arc.Arc;
import io.quarkus.runtime.BlockingOperationControl;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.credential.CertificateCredential;
import io.quarkus.security.credential.TokenCredential;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.smallrye.common.vertx.VertxContext;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.subscription.Cancellable;
import io.vertx.core.Context;
import io.vertx.core.Vertx;
import io.vertx.ext.web.RoutingContext;

class OAuth2ProtocolRequestContextTest {
    private static final int TIMEOUT = 10;
    private static final String REDIRECT = "https://client.example/callback";
    private static final String ACCESS_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addClasses(
                            Mode.class,
                            TokenGrantHttpFixture.class,
                            Flow.class,
                            Visit.class,
                            Scope.class,
                            Probes.class,
                            RequestState.class,
                            Clients.class,
                            Secrets.class,
                            Authorizations.class,
                            Customizer.class,
                            ResourceOwners.class)
                            .addAsResource("privateKey.pem")
                            .addAsResource("publicKey.pem")
                            .addAsResource("mtls/self-client.pem")
                            .addAsResource(
                                    new StringAsset(
                                            """
                                                    quarkus.authorization-server.issuer=https://issuer.example
                                                    quarkus.authorization-server.oidc.enabled=true
                                                    quarkus.authorization-server.signing.key-id=test-key
                                                    quarkus.authorization-server.signing.private-key-location=classpath:privateKey.pem
                                                    quarkus.authorization-server.signing.public-key-location=classpath:publicKey.pem
                                                    """),
                                    "application.properties"));

    @Inject
    Probes probes;
    @Inject
    Authorizations authorizations;
    @Inject
    Instance<TokenGrantHandler> handlers;
    @Inject
    Vertx vertx;
    @Inject
    IdentityProviderManager identities;
    @Inject
    CurrentVertxRequest currentRequest;
    @TestHTTPResource
    URI baseUri;

    @ParameterizedTest
    @ValueSource(strings = {
            "CODE",
            "REFRESH",
            "DEVICE",
            "EXCHANGE",
            "PASSWORD",
            "INTROSPECTION",
            "REVOCATION",
            "PUBLIC_CODE",
            "PUBLIC_DEVICE",
            "USERINFO"
    })
    void realHttpExecutesRepositoryAndProtocolWorkWithRequestScope(String modeName)
            throws Exception {
        Mode mode = Mode.valueOf(modeName);
        Flow flow = create(mode);
        assertEquals(200, request(flow).statusCode());
        assertReleased(flow);
        if (mode.issues) {
            assertSameScope(flow, "customize", "save");
            assertEquals(1, flow.saves.get());
        } else if (mode == Mode.INTROSPECTION) {
            assertSameScope(flow, "find", "client-by-id");
        } else if (mode == Mode.REVOCATION) {
            assertSameScope(flow, "find", "save");
        }
        if (!mode.publicClient && mode != Mode.USERINFO) {
            assertSameScope(flow, "client", "secret");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "CODE",
            "REFRESH",
            "DEVICE",
            "EXCHANGE",
            "PASSWORD",
            "INTROSPECTION",
            "REVOCATION"
    })
    void protocolFailuresReleaseScopeWithoutSaving(String modeName) throws Exception {
        Mode mode = Mode.valueOf(modeName);
        Flow flow = create(mode);
        flow.failAt = mode.issues ? "customize" : mode == Mode.INTROSPECTION ? "client-by-id" : "save";
        Response response = request(flow);
        assertEquals(400, response.statusCode());
        assertEquals("server_error", response.path("error"));
        assertReleased(flow);
        assertEquals(0, flow.saves.get());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "CODE",
            "REFRESH",
            "DEVICE",
            "EXCHANGE",
            "PASSWORD",
            "INTROSPECTION",
            "REVOCATION"
    })
    void overlappingHttpRequestsKeepIndependentScopes(String modeName) throws Exception {
        Mode mode = Mode.valueOf(modeName);
        Flow first = create(mode);
        Flow second = create(mode);
        first.blockAt = second.blockAt = mode.issues
                ? "customize"
                : mode == Mode.INTROSPECTION ? "client-by-id" : "save";
        try (var executor = Executors.newFixedThreadPool(2)) {
            var firstResponse = executor.submit(() -> request(first));
            var secondResponse = executor.submit(() -> request(second));
            try {
                first.entered.get(TIMEOUT, TimeUnit.SECONDS);
                second.entered.get(TIMEOUT, TimeUnit.SECONDS);
                Scope firstScope = first.scopes.get(first.visits.getLast().scopeId());
                Scope secondScope = second.scopes.get(second.visits.getLast().scopeId());
                assertNotSame(firstScope.context, secondScope.context);
                assertEquals(0, firstScope.destructions.get());
                assertEquals(0, secondScope.destructions.get());
            } finally {
                first.release.complete(null);
                second.release.complete(null);
            }
            assertEquals(200, firstResponse.get(TIMEOUT, TimeUnit.SECONDS).statusCode());
            assertEquals(200, secondResponse.get(TIMEOUT, TimeUnit.SECONDS).statusCode());
        }
        assertReleased(first);
        assertReleased(second);
        assertTrue(first.scopes.keySet().stream().noneMatch(second.scopes::containsKey));
    }

    @ParameterizedTest
    @ValueSource(strings = { "CODE", "REFRESH", "DEVICE", "EXCHANGE", "PASSWORD" })
    void cancelledGrantKeepsScopeUntilBlockingIssuanceExits(String modeName) throws Exception {
        Mode mode = Mode.valueOf(modeName);
        Flow flow = create(mode);
        flow.blockAt = "customize";
        var authentication = authentication(flow);
        var handler = handlers.stream()
                .filter(h -> h.getGrantType().equals(authentication.getGrantType()))
                .findFirst()
                .orElseThrow();
        CompletableFuture<Cancellable> subscription = new CompletableFuture<>();
        AtomicInteger callbacks = new AtomicInteger();
        Context context = VertxContext.createNewDuplicatedContext(vertx.getOrCreateContext());
        context.runOnContext(
                ignored -> {
                    try {
                        assertFalse(Arc.container().requestContext().isActive());
                        var pending = handler.handle(
                                TokenGrantHttpFixture.context(
                                        parameters(flow),
                                        authentication.getClientPrincipal()));
                        assertTrue(
                                flow.visits.isEmpty(),
                                "Protocol execution is deferred until subscription");
                        subscription.complete(
                                pending.subscribe()
                                        .with(
                                                item -> callbacks.incrementAndGet(),
                                                failure -> callbacks.incrementAndGet()));
                    } catch (Throwable failure) {
                        subscription.completeExceptionally(failure);
                    }
                });
        Cancellable cancellable = subscription.get(TIMEOUT, TimeUnit.SECONDS);
        try {
            flow.entered.get(TIMEOUT, TimeUnit.SECONDS);
            cancellable.cancel();
            assertTrue(
                    flow.scopes.values().stream().allMatch(scope -> scope.destructions.get() == 0));
        } finally {
            flow.release.complete(null);
        }
        assertReleased(flow);
        assertEquals(1, flow.saves.get());
        assertEquals(0, callbacks.get());
        assertSameScope(flow, "customize", "save");
    }

    @ParameterizedTest
    @ValueSource(strings = { "CODE", "PUBLIC_CODE", "PUBLIC_DEVICE", "USERINFO" })
    void authenticationFailureReleasesItsScope(String modeName) throws Exception {
        Flow flow = create(Mode.valueOf(modeName));
        flow.rejectCredential = true;
        assertEquals(401, request(flow).statusCode());
        assertReleased(flow);
        assertEquals(0, flow.saves.get());
        assertTrue(flow.visits.stream().noneMatch(v -> v.stage().equals("customize")));
    }

    @ParameterizedTest
    @CsvSource({
            "BASIC, true", "BASIC, false", "PUBLIC, true", "PUBLIC, false",
            "JWT, true", "JWT, false", "X509, true", "X509, false", "ACCESS_TOKEN, true", "ACCESS_TOKEN, false"
    })
    void identityProvidersSupportRequestsWithAndWithoutHttpContext(String provider, boolean withHttp)
            throws Exception {
        Flow flow = create(provider.equals("PUBLIC") ? Mode.PUBLIC_CODE : Mode.CODE);
        // Reject after repository access to isolate the execution boundary from credential validation.
        flow.rejectCredential = true;
        flow.httpRequest = withHttp;
        AuthenticationRequest authentication;
        if (provider.equals("X509")) {
            try (var pem = getClass().getClassLoader().getResourceAsStream("mtls/self-client.pem")) {
                var certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(pem);
                authentication = new X509ClientCertificateAuthenticationRequest(flow.id,
                        new CertificateCredential(certificate));
            }
        } else {
            authentication = switch (provider) {
                case "BASIC" -> new OAuth2ClientAuthenticationToken(flow.id,
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "secret");
                case "PUBLIC" -> new OAuth2ClientAuthenticationToken(flow.id, ClientAuthenticationMethod.NONE, null);
                case "JWT" -> new JwtClientAssertionAuthenticationRequest(flow.id, "unused");
                case "ACCESS_TOKEN" -> new OAuth2AccessTokenAuthenticationRequest(
                        new TokenCredential(flow.id + "-access", "bearer"));
                default -> throw new IllegalArgumentException(provider);
            };
        }
        if (withHttp) {
            var http = TokenGrantHttpFixture.context(Map.of(), identity("alice"));
            http.request().headers().set("X-Request-Id", flow.id);
            HttpSecurityUtils.setRoutingContextAttribute(authentication, http);
        }
        CompletableFuture<Throwable> completed = new CompletableFuture<>();
        Context context = VertxContext.createNewDuplicatedContext(this.vertx.getOrCreateContext());
        context.runOnContext(ignored -> {
            try {
                assertFalse(Arc.container().requestContext().isActive());
                this.identities.authenticate(authentication).subscribe().with(
                        result -> completed.completeExceptionally(new AssertionError("Authentication must fail")),
                        completed::complete);
            } catch (Throwable failure) {
                completed.completeExceptionally(failure);
            }
        });
        var failure = assertInstanceOf(OAuth2AuthenticationException.class, completed.get(TIMEOUT, TimeUnit.SECONDS));
        assertEquals(provider.equals("ACCESS_TOKEN") ? "invalid_token" : "invalid_client",
                failure.getError().getErrorCode());
        assertReleased(flow);
        assertEquals(0, flow.saves.get());
    }

    @Test
    void programmaticAuthenticationPreservesCallerOwnedHttpContext() throws Exception {
        Flow flow = create(Mode.CODE);
        flow.httpRequest = true;
        var authentication = new OAuth2ClientAuthenticationToken(flow.id,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "secret");
        var http = TokenGrantHttpFixture.context(Map.of(), identity("alice"));
        http.request().headers().set("X-Request-Id", flow.id);
        CompletableFuture<Void> completed = new CompletableFuture<>();
        Context context = VertxContext.createNewDuplicatedContext(this.vertx.getOrCreateContext());
        context.runOnContext(ignored -> {
            var requestScope = Arc.container().requestContext();
            requestScope.activate();
            var ownedState = requestScope.getState();
            this.currentRequest.setCurrent(http);
            this.identities.authenticate(authentication).subscribe().with(result -> {
                try {
                    assertEquals(flow.id, result.getPrincipal().getName());
                    assertTrue(Context.isOnEventLoopThread());
                    assertSame(ownedState, requestScope.getState());
                    assertSame(http, this.currentRequest.getCurrent());
                    assertTrue(flow.scopes.values().stream().allMatch(scope -> scope.destructions.get() == 0));
                    requestScope.terminate();
                    completed.complete(null);
                } catch (Throwable failure) {
                    requestScope.terminate();
                    completed.completeExceptionally(failure);
                }
            }, failure -> {
                requestScope.terminate();
                completed.completeExceptionally(failure);
            });
        });
        completed.get(TIMEOUT, TimeUnit.SECONDS);
        assertReleased(flow);
        assertSameScope(flow, "client", "secret");
    }

    @Test
    void repeatedAuthenticationAndProtocolPhasesDoNotLeakRequestScopes() throws Exception {
        for (int iteration = 0; iteration < 10; iteration++) {
            for (String mode : List.of("CODE", "REFRESH", "DEVICE", "EXCHANGE", "PASSWORD")) {
                cancelledGrantKeepsScopeUntilBlockingIssuanceExits(mode);
                overlappingHttpRequestsKeepIndependentScopes(mode);
                protocolFailuresReleaseScopeWithoutSaving(mode);
            }
            overlappingHttpRequestsKeepIndependentScopes("INTROSPECTION");
            overlappingHttpRequestsKeepIndependentScopes("REVOCATION");
        }
    }

    @Test
    void passwordWaitsForAsyncIdentityWithoutBlockingTheEventLoop() throws Exception {
        Flow flow = create(Mode.PASSWORD);
        flow.delayIdentity = true;
        try (var executor = Executors.newSingleThreadExecutor()) {
            var response = executor.submit(() -> request(flow));
            try {
                flow.identityEntered.get(TIMEOUT, TimeUnit.SECONDS);
                assertTrue(flow.visits.stream().noneMatch(v -> v.stage().equals("customize")));
                CompletableFuture<Void> responsive = new CompletableFuture<>();
                flow.identityContext.runOnContext(ignored -> responsive.complete(null));
                responsive.get(TIMEOUT, TimeUnit.SECONDS);
            } finally {
                flow.identity.complete(identity("alice"));
            }
            assertEquals(200, response.get(TIMEOUT, TimeUnit.SECONDS).statusCode());
        }
        assertReleased(flow);
        assertSameScope(flow, "customize", "save");
        assertArrayEquals(new char[6], flow.credentials);
    }

    @Test
    void failedAsyncIdentityDoesNotStartIssuanceAndErasesCredentials() throws Exception {
        Flow flow = create(Mode.PASSWORD);
        flow.identity.completeExceptionally(new AuthenticationFailedException());
        Response response = request(flow);
        assertEquals(400, response.statusCode());
        assertEquals("invalid_grant", response.path("error"));
        assertReleased(flow);
        assertEquals(0, flow.saves.get());
        assertTrue(flow.visits.stream().noneMatch(v -> v.stage().equals("customize")));
        assertArrayEquals(new char[6], flow.credentials);
    }

    private Flow create(Mode mode) {
        Flow flow = new Flow(mode);
        probes.flows.put(flow.id, flow);
        Instant now = Instant.now();
        Set<String> scopes = mode == Mode.USERINFO ? Set.of("openid", "message.read") : Set.of("message.read");
        OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://issuer.example/oauth2/authorize")
                .clientId(flow.id)
                .redirectUri(REDIRECT)
                .scopes(scopes)
                .build();
        if (mode == Mode.PUBLIC_CODE) {
            request = OAuth2AuthorizationRequest.from(request)
                    .additionalParameters(
                            Map.of(
                                    "code_challenge",
                                    "fR4ifSAEy-7Mu6g7FHZulPKrtjqdAnUCwRFAJt2JFsA",
                                    "code_challenge_method",
                                    "S256"))
                    .build();
        }
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(flow.client)
                .principalName("alice")
                .authorizationGrantType(
                        mode == Mode.DEVICE || mode == Mode.PUBLIC_DEVICE
                                ? AuthorizationGrantType.DEVICE_CODE
                                : AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(scopes)
                .attribute(SecurityIdentity.class.getName(), identity("alice"))
                .attribute(OAuth2AuthorizationRequest.class.getName(), request)
                .authorizationCode(
                        new OAuth2AuthorizationCode(
                                flow.id + "-code", now, now.plusSeconds(300)))
                .token(new OAuth2DeviceCode(flow.id + "-device", now, now.plusSeconds(300)))
                .token(
                        new OAuth2UserCode(flow.id + "-user", now, now.plusSeconds(300)),
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                true))
                .refreshToken(
                        new OAuth2RefreshToken(
                                flow.id + "-refresh", now, now.plusSeconds(3600)))
                .token(
                        new OAuth2AccessToken(
                                OAuth2AccessToken.TokenType.BEARER,
                                flow.id + "-access",
                                now,
                                now.plusSeconds(300),
                                scopes),
                        metadata -> {
                            metadata.put(
                                    OAuth2TokenFormat.class.getName(),
                                    OAuth2TokenFormat.REFERENCE.getValue());
                            metadata.put(
                                    OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                    Map.of("sub", "alice"));
                        })
                .token(
                        new OidcIdToken(
                                flow.id + "-id",
                                now,
                                now.plusSeconds(300),
                                Map.of("sub", "alice")))
                .build();
        authorizations.delegate.save(authorization);
        return flow;
    }

    private Response request(Flow flow) {
        flow.httpRequest = true;
        var request = given().baseUri(baseUri.toString()).contentType(ContentType.URLENC)
                .header("X-Request-Id", flow.id);
        if (flow.mode == Mode.USERINFO) {
            return request.header("Authorization", "Bearer " + flow.id + "-access")
                    .get("/userinfo");
        }
        if (flow.mode.publicClient)
            request.formParam("client_id", flow.id);
        else
            request.auth().preemptive().basic(flow.id, "secret");
        return request.formParams(parameters(flow))
                .post(
                        flow.mode == Mode.INTROSPECTION
                                ? "/oauth2/introspect"
                                : flow.mode == Mode.REVOCATION
                                        ? "/oauth2/revoke"
                                        : "/oauth2/token");
    }

    private Map<String, String> parameters(Flow flow) {
        return switch (flow.mode) {
            case CODE ->
                Map.of(
                        "grant_type",
                        "authorization_code",
                        "code",
                        flow.id + "-code",
                        "redirect_uri",
                        REDIRECT);
            case PUBLIC_CODE ->
                Map.of(
                        "grant_type",
                        "authorization_code",
                        "code",
                        flow.id + "-code",
                        "redirect_uri",
                        REDIRECT,
                        "code_verifier",
                        "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG");
            case REFRESH ->
                Map.of("grant_type", "refresh_token", "refresh_token", flow.id + "-refresh");
            case DEVICE, PUBLIC_DEVICE ->
                Map.of(
                        "grant_type",
                        AuthorizationGrantType.DEVICE_CODE.getValue(),
                        "device_code",
                        flow.id + "-device");
            case EXCHANGE ->
                Map.of(
                        "grant_type",
                        AuthorizationGrantType.TOKEN_EXCHANGE.getValue(),
                        "subject_token",
                        flow.id + "-access",
                        "subject_token_type",
                        ACCESS_TYPE);
            case PASSWORD ->
                Map.of("grant_type", "password", "username", flow.id, "password", "secret");
            default -> Map.of("token", flow.id + "-access");
        };
    }

    private TokenGrantRequest authentication(Flow flow) {
        SecurityIdentity principal = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(flow.id))
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                        flow.client)
                .addAttribute(
                        OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE,
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .build();
        return switch (flow.mode) {
            case CODE ->
                new AuthorizationCodeExchangeRequest(
                        flow.id + "-code", principal, REDIRECT, Map.of());
            case REFRESH ->
                new RefreshTokenRequest(flow.id + "-refresh", principal, Set.of(), Map.of());
            case DEVICE -> new DeviceCodeExchangeRequest(flow.id + "-device", principal, Map.of());
            case EXCHANGE ->
                new TokenExchangeRequest(
                        List.of(),
                        List.of(),
                        Set.of(),
                        ACCESS_TYPE,
                        flow.id + "-access",
                        ACCESS_TYPE,
                        null,
                        null,
                        principal,
                        Map.of());
            case PASSWORD ->
                new PasswordGrantRequest(principal, flow.id, "secret", Map.of(), Set.of());
            default -> throw new IllegalArgumentException(flow.mode.name());
        };
    }

    private static SecurityIdentity identity(String name) {
        return QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal(name)).build();
    }

    private static void assertReleased(Flow flow) throws Exception {
        assertFalse(flow.scopes.isEmpty());
        for (Scope scope : flow.scopes.values()) {
            try {
                scope.destroyed.get(TIMEOUT, TimeUnit.SECONDS);
            } catch (java.util.concurrent.TimeoutException failure) {
                throw new AssertionError(
                        "Unreleased scope: flow="
                                + flow.id
                                + " mode="
                                + flow.mode
                                + " visits="
                                + flow.visits
                                + " scopes="
                                + flow.scopes.entrySet().stream()
                                        .map(
                                                entry -> entry.getKey()
                                                        + ":destroyed="
                                                        + entry.getValue().destructions
                                                                .get()
                                                        + ":context="
                                                        + entry.getValue().context)
                                        .toList(),
                        failure);
            }
            assertEquals(1, scope.destructions.get());
        }
    }

    private static void assertSameScope(Flow flow, String first, String second) {
        Visit before = flow.visits.stream()
                .filter(v -> v.stage().equals(first))
                .reduce((a, b) -> b)
                .orElseThrow();
        Visit after = flow.visits.stream()
                .filter(v -> v.stage().equals(second))
                .reduce((a, b) -> b)
                .orElseThrow();
        assertEquals(before.scopeId(), after.scopeId(), first + " and " + second);
    }

    enum Mode {
        CODE(true, false),
        REFRESH(true, false),
        DEVICE(true, false),
        EXCHANGE(true, false),
        PASSWORD(true, false),
        INTROSPECTION(false, false),
        REVOCATION(false, false),
        PUBLIC_CODE(true, true),
        PUBLIC_DEVICE(true, true),
        USERINFO(false, false);

        final boolean issues;
        final boolean publicClient;

        Mode(boolean issues, boolean publicClient) {
            this.issues = issues;
            this.publicClient = publicClient;
        }
    }

    static class Flow {
        final String id = UUID.randomUUID().toString();
        final Mode mode;
        final RegisteredClient client;
        final Map<String, Scope> scopes = new ConcurrentHashMap<>();
        final List<Visit> visits = new CopyOnWriteArrayList<>();
        final AtomicInteger saves = new AtomicInteger();
        final CompletableFuture<Void> entered = new CompletableFuture<>();
        final CompletableFuture<Void> release = new CompletableFuture<>();
        final CompletableFuture<Void> identityEntered = new CompletableFuture<>();
        final CompletableFuture<SecurityIdentity> identity = new CompletableFuture<>();
        volatile String blockAt;
        volatile String failAt;
        volatile boolean delayIdentity;
        volatile boolean rejectCredential;
        volatile boolean httpRequest;
        volatile Context identityContext;
        volatile char[] credentials;

        Flow(Mode mode) {
            this.mode = mode;
            client = RegisteredClient.withId(id)
                    .clientId(id)
                    .clientSecret(id)
                    .clientAuthenticationMethod(
                            mode.publicClient
                                    ? ClientAuthenticationMethod.NONE
                                    : ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                    .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                    .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                    .redirectUri(REDIRECT)
                    .scope("message.read")
                    .clientSettings(
                            ClientSettings.builder()
                                    .requireProofKey(mode == Mode.PUBLIC_CODE)
                                    .build())
                    .build();
        }
    }

    record Visit(String stage, String scopeId) {
    }

    static class Scope {
        final Context context = Vertx.currentContext();
        final Thread worker = Thread.currentThread();
        final AtomicInteger destructions = new AtomicInteger();
        final CompletableFuture<Void> destroyed = new CompletableFuture<>();
    }

    @Singleton
    public static class Probes {
        final Map<String, Flow> flows = new ConcurrentHashMap<>();

        Flow token(String token) {
            return flows.values().stream()
                    .filter(flow -> token.startsWith(flow.id))
                    .findFirst()
                    .orElseThrow();
        }
    }

    @RequestScoped
    public static class RequestState {
        @Inject
        RoutingContext http;
        final String id = UUID.randomUUID().toString();
        Scope scope;
        Flow flow;

        void visit(Flow flow, String stage) {
            assertTrue(Arc.container().requestContext().isActive());
            assertTrue(BlockingOperationControl.isBlockingAllowed());
            assertFalse(Context.isOnEventLoopThread());
            assertTrue(VertxContext.isDuplicatedContext(Vertx.currentContext()));
            if (flow.httpRequest) {
                assertEquals(flow.id, this.http.request().getHeader("X-Request-Id"));
            }
            if (this.flow == null) {
                this.flow = flow;
                this.scope = new Scope();
                flow.scopes.put(id, scope);
            }
            assertSame(this.flow, flow);
            assertSame(scope.context, Vertx.currentContext());
            assertSame(scope.worker, Thread.currentThread());
            flow.visits.add(new Visit(stage, id));
            if (stage.equals(flow.blockAt)) {
                flow.entered.complete(null);
                try {
                    flow.release.get(TIMEOUT, TimeUnit.SECONDS);
                } catch (Exception failure) {
                    throw new IllegalStateException(failure);
                }
                assertEquals(
                        0,
                        scope.destructions.get(),
                        "Scope must remain usable until blocking work exits");
            }
            if (stage.equals(flow.failAt))
                throw new IllegalStateException("Simulated " + stage + " failure");
        }

        @PreDestroy
        void destroy() {
            if (scope != null) {
                scope.destructions.incrementAndGet();
                scope.destroyed.complete(null);
            }
        }
    }

    @Singleton
    public static class Clients implements RegisteredClientRepository {
        @Inject
        Probes probes;
        @Inject
        RequestState state;

        public void save(RegisteredClient client) {
            throw new UnsupportedOperationException();
        }

        public RegisteredClient findByClientId(String id) {
            Flow flow = probes.flows.get(id);
            state.visit(flow, "client");
            return flow.rejectCredential ? null : flow.client;
        }

        public RegisteredClient findById(String id) {
            Flow flow = probes.flows.get(id);
            state.visit(flow, "client-by-id");
            return flow.client;
        }
    }

    @Singleton
    public static class Secrets implements ClientSecretVerifier {
        @Inject
        Probes probes;
        @Inject
        RequestState state;

        public boolean matches(String presented, String stored) {
            state.visit(probes.flows.get(stored), "secret");
            return "secret".equals(presented);
        }
    }

    @Singleton
    public static class Authorizations implements OAuth2AuthorizationService {
        final InMemoryOAuth2AuthorizationService delegate = new InMemoryOAuth2AuthorizationService();
        @Inject
        Probes probes;
        @Inject
        RequestState state;

        public void save(OAuth2Authorization authorization) {
            Flow flow = probes.flows.get(authorization.getRegisteredClientId());
            state.visit(flow, "save");
            delegate.save(authorization);
            flow.saves.incrementAndGet();
        }

        public void remove(OAuth2Authorization authorization) {
            delegate.remove(authorization);
        }

        public OAuth2Authorization findById(String id) {
            return delegate.findById(id);
        }

        public OAuth2Authorization findByToken(String token, OAuth2TokenType type) {
            Flow flow = probes.token(token);
            state.visit(flow, "find");
            return flow.rejectCredential ? null : delegate.findByToken(token, type);
        }
    }

    @Singleton
    public static class Customizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
        @Inject
        Probes probes;
        @Inject
        RequestState state;

        public void customize(JwtEncodingContext context) {
            state.visit(probes.flows.get(context.getRegisteredClient().getClientId()), "customize");
        }
    }

    @Singleton
    public static class ResourceOwners
            implements IdentityProvider<UsernamePasswordAuthenticationRequest> {
        @Inject
        Probes probes;

        public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
            return UsernamePasswordAuthenticationRequest.class;
        }

        public Uni<SecurityIdentity> authenticate(
                UsernamePasswordAuthenticationRequest request,
                AuthenticationRequestContext context) {
            Flow flow = probes.flows.get(request.getUsername());
            flow.credentials = request.getPassword().getPassword();
            flow.identityContext = Vertx.currentContext();
            flow.identityEntered.complete(null);
            if (!flow.delayIdentity)
                flow.identity.complete(identity("alice"));
            return Uni.createFrom().completionStage(flow.identity);
        }
    }
}
