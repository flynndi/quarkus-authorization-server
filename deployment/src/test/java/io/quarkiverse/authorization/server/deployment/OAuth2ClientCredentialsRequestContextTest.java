package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.grant.TokenGrantRequest;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequestContext;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequestValidator;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.grant.clientcredentials.web.ClientCredentialsGrantHandler;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.arc.Arc;
import io.quarkus.runtime.BlockingOperationControl;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.test.common.http.TestHTTPResource;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.smallrye.common.vertx.VertxContext;
import io.smallrye.mutiny.subscription.Cancellable;
import io.vertx.core.Context;
import io.vertx.core.Vertx;

class OAuth2ClientCredentialsRequestContextTest {

    private static final int TIMEOUT_SECONDS = 10;

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addClass(TokenGrantHttpFixture.class)
                            .addAsResource("privateKey.pem")
                            .addAsResource("publicKey.pem")
                            .addClasses(
                                    ProbeValidatorProducer.class,
                                    ProbeCustomizer.class,
                                    ProbeAuthorizationService.class,
                                    RequestState.class,
                                    Observations.class,
                                    Observation.class)
                            .addAsResource(
                                    new StringAsset(
                                            """
                                                    quarkus.authorization-server.issuer=https://issuer.example
                                                    quarkus.authorization-server.signing.key-id=test-key
                                                    quarkus.authorization-server.signing.private-key-location=classpath:privateKey.pem
                                                    quarkus.authorization-server.signing.public-key-location=classpath:publicKey.pem
                                                    quarkus.authorization-server.clients.machine.client-secret=$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK
                                                    quarkus.authorization-server.clients.machine.authorization-grant-types=client_credentials
                                                    quarkus.authorization-server.clients.machine.scopes=message.read
                                                    """),
                                    "application.properties"));

    @Inject
    Observations observations;
    @Inject
    ProbeAuthorizationService authorizations;
    @Inject
    RegisteredClientRepository clients;
    @Inject
    ClientCredentialsGrantHandler handler;
    @Inject
    io.quarkus.vertx.http.runtime.CurrentVertxRequest currentRequest;
    @Inject
    Vertx vertx;
    @TestHTTPResource
    URI baseUri;

    @Test
    void validatorCustomizerAndServiceShareRequestScopeOnWorkerAndReleaseItAfterSuccess()
            throws Exception {
        Observation observation = this.observations.create();

        var response = tokenRequest(observation);
        assertEquals(200, response.statusCode(), () -> String.valueOf(observation.failure));
        String accessToken = response.then()
                .body("token_type", equalTo("Bearer"))
                .extract()
                .path("access_token");

        assertReleased(observation, List.of("validator", "customizer", "save"));
        assertNotNull(this.authorizations.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN));
    }

    @ParameterizedTest
    @ValueSource(strings = { "validator", "customizer", "save" })
    void releasesRequestScopeAfterProtocolOrStorageFailure(String failingStage) throws Exception {
        Observation observation = this.observations.create();
        observation.failingStage = failingStage;

        String errorCode = switch (failingStage) {
            case "validator" -> "invalid_request";
            case "customizer" -> "invalid_scope";
            default -> "server_error";
        };
        tokenRequest(observation).then().statusCode(400).body("error", equalTo(errorCode));

        List<String> stages = switch (failingStage) {
            case "validator" -> List.of("validator");
            case "customizer" -> List.of("validator", "customizer");
            default -> List.of("validator", "customizer", "save");
        };
        assertReleased(observation, stages);
        assertNull(observation.saved);
    }

    @Test
    void overlappingHttpRequestsUseDifferentRequestScopeInstances() throws Exception {
        Observation first = this.observations.create();
        Observation second = this.observations.create();
        first.block = true;
        second.block = true;
        first.blockingStage = "validator";
        second.blockingStage = "validator";
        try (var executor = Executors.newFixedThreadPool(2)) {
            var firstResponse = executor.submit(() -> tokenRequest(first));
            var secondResponse = executor.submit(() -> tokenRequest(second));
            try {
                first.entered.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                second.entered.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                assertNotEquals(first.requestStateId, second.requestStateId);
                assertNotSame(first.vertxContext, second.vertxContext);
                assertFalse(first.destroyed.isDone());
                assertFalse(second.destroyed.isDone());
            } finally {
                first.release.complete(null);
                second.release.complete(null);
            }
            firstResponse.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).then().statusCode(200);
            secondResponse.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).then().statusCode(200);
        }
        assertReleased(first, List.of("validator", "customizer", "save"));
        assertReleased(second, List.of("validator", "customizer", "save"));
    }

    @Test
    void disconnectDoesNotDestroyScopeWhileBlockingIssuanceIsStillRunning() throws Exception {
        Observation observation = this.observations.create();
        observation.block = true;
        observation.observeDisconnect = true;
        String body = "grant_type=client_credentials&scope=message.read&probe_id=" + observation.id;
        String credentials = Base64.getEncoder()
                .encodeToString(
                        "machine:client-secret".getBytes(StandardCharsets.US_ASCII));
        try {
            try (Socket socket = new Socket(this.baseUri.getHost(), this.baseUri.getPort())) {
                socket.setSoLinger(true, 0);
                String request = "POST /oauth2/token HTTP/1.1\r\nHost: "
                        + this.baseUri.getAuthority()
                        + "\r\nAuthorization: Basic "
                        + credentials
                        + "\r\n"
                        + "Content-Type: application/x-www-form-urlencoded\r\n"
                        + "Content-Length: "
                        + body.length()
                        + "\r\n\r\n"
                        + body;
                socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
                socket.getOutputStream().flush();
                observation.entered.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
            observation.disconnected.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            assertFalse(observation.destroyed.isDone());
        } finally {
            observation.release.complete(null);
        }
        // A disconnected client does not roll back already-running blocking issuance.
        assertReleased(observation, List.of("validator", "customizer", "save"));
        assertNotNull(observation.saved);
        Observation next = this.observations.create();
        tokenRequest(next).then().statusCode(200);
        assertReleased(next, List.of("validator", "customizer", "save"));
        assertNotEquals(observation.requestStateId, next.requestStateId);
    }

    @Test
    void cancellingSubscriptionKeepsScopeAliveUntilBlockingWorkExits() throws Exception {
        Observation observation = this.observations.create();
        observation.block = true;
        var authentication = authentication(observation);
        CompletableFuture<Cancellable> subscription = new CompletableFuture<>();
        AtomicInteger callbacks = new AtomicInteger();
        Context context = VertxContext.createNewDuplicatedContext(this.vertx.getOrCreateContext());
        context.runOnContext(
                ignored -> {
                    try {
                        assertTrue(Context.isOnEventLoopThread());
                        assertFalse(Arc.container().requestContext().isActive());
                        var pending = this.handler.handle(authentication);
                        assertFalse(
                                observation.entered.isDone(),
                                "Execution must be deferred until subscription");
                        subscription.complete(
                                pending.subscribe()
                                        .with(
                                                result -> callbacks.incrementAndGet(),
                                                failure -> callbacks.incrementAndGet()));
                    } catch (Throwable failure) {
                        subscription.completeExceptionally(failure);
                    }
                });
        Cancellable cancellable = subscription.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        try {
            observation.entered.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            cancellable.cancel();
            assertFalse(observation.destroyed.isDone());
        } finally {
            observation.release.complete(null);
        }
        assertReleased(observation, List.of("validator", "customizer", "save"));
        assertNotNull(observation.saved);
        assertEquals(0, callbacks.get());
    }

    @Test
    void returnsToEventLoopWithCreatedContextDeactivated() throws Exception {
        Observation observation = this.observations.create();
        var authentication = authentication(observation);
        CompletableFuture<Void> completed = new CompletableFuture<>();
        Context context = VertxContext.createNewDuplicatedContext(this.vertx.getOrCreateContext());
        context.runOnContext(
                ignored -> {
                    try {
                        assertFalse(Arc.container().requestContext().isActive());
                        var pending = this.handler.handle(authentication);
                        assertFalse(observation.entered.isDone());
                        pending.subscribe()
                                .with(
                                        result -> {
                                            try {
                                                assertTrue(Context.isOnEventLoopThread());
                                                assertSame(context, Vertx.currentContext());
                                                assertFalse(
                                                        Arc.container()
                                                                .requestContext()
                                                                .isActive());
                                                assertEquals(1, observation.destructions.get());
                                                completed.complete(null);
                                            } catch (Throwable failure) {
                                                completed.completeExceptionally(failure);
                                            }
                                        },
                                        completed::completeExceptionally);
                    } catch (Throwable failure) {
                        completed.completeExceptionally(failure);
                    }
                });
        completed.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertReleased(observation, List.of("validator", "customizer", "save"));
    }

    @Test
    void reusesExistingContextAndLeavesItsDestructionToItsOwner() throws Exception {
        Observation observation = this.observations.create();
        var authentication = authentication(observation);
        CompletableFuture<Void> completed = new CompletableFuture<>();
        Context context = VertxContext.createNewDuplicatedContext(this.vertx.getOrCreateContext());
        context.runOnContext(
                ignored -> {
                    var requestContext = Arc.container().requestContext();
                    requestContext.activate();
                    var ownedState = requestContext.getState();
                    var previousHttpContext = TokenGrantHttpFixture.context(
                            Map.of(),
                            QuarkusSecurityIdentity.builder().setAnonymous(true).build());
                    this.currentRequest.setCurrent(previousHttpContext);
                    this.handler
                            .handle(authentication)
                            .subscribe()
                            .with(
                                    result -> {
                                        try {
                                            assertTrue(Context.isOnEventLoopThread());
                                            assertTrue(requestContext.isActive());
                                            assertSame(ownedState, requestContext.getState());
                                            assertSame(
                                                    previousHttpContext,
                                                    this.currentRequest.getCurrent());
                                            assertEquals(0, observation.destructions.get());
                                            requestContext.terminate();
                                            assertFalse(requestContext.isActive());
                                            completed.complete(null);
                                        } catch (Throwable failure) {
                                            requestContext.terminate();
                                            completed.completeExceptionally(failure);
                                        }
                                    },
                                    failure -> {
                                        requestContext.terminate();
                                        completed.completeExceptionally(failure);
                                    });
                });
        completed.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertReleased(observation, List.of("validator", "customizer", "save"));
    }

    private static Response tokenRequest(Observation observation) {
        return given().auth()
                .preemptive()
                .basic("machine", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials")
                .formParam("scope", "message.read")
                .formParam("probe_id", observation.id)
                .post("/oauth2/token");
    }

    private io.vertx.ext.web.RoutingContext authentication(Observation observation) {
        var client = this.clients.findByClientId("machine");
        var identity = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(client.getClientId()))
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, client)
                .build();
        return TokenGrantHttpFixture.context(
                Map.of(
                        "grant_type",
                        "client_credentials",
                        "scope",
                        "message.read",
                        "probe_id",
                        observation.id),
                identity);
    }

    private static void assertReleased(Observation observation, List<String> stages)
            throws Exception {
        observation.destroyed.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertEquals(stages, observation.visits);
        assertEquals(1, observation.destructions.get());
    }

    public static class Observation {
        final String id = UUID.randomUUID().toString();
        final List<String> visits = new CopyOnWriteArrayList<>();
        final AtomicInteger destructions = new AtomicInteger();
        final CompletableFuture<Void> destroyed = new CompletableFuture<>();
        final CompletableFuture<Void> entered = new CompletableFuture<>();
        final CompletableFuture<Void> release = new CompletableFuture<>();
        final CompletableFuture<Void> disconnected = new CompletableFuture<>();
        volatile boolean block;
        volatile String blockingStage = "customizer";
        volatile boolean observeDisconnect;
        volatile String failingStage;
        OAuth2Authorization saved;
        UUID requestStateId;
        Context vertxContext;
        Thread worker;
        volatile Throwable failure;

        void awaitRelease(String stage) {
            if (this.block && stage.equals(this.blockingStage)) {
                this.entered.complete(null);
                try {
                    this.release.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                } catch (Exception failure) {
                    throw new IllegalStateException(
                            "Timed out waiting for test to release issuance", failure);
                }
            }
        }
    }

    @Singleton
    public static class Observations {
        final ConcurrentHashMap<String, Observation> requests = new ConcurrentHashMap<>();

        Observation create() {
            Observation observation = new Observation();
            this.requests.put(observation.id, observation);
            return observation;
        }
    }

    @RequestScoped
    public static class RequestState {
        private final UUID id = UUID.randomUUID();
        private Observation observation;

        void attach(Observation observation) {
            assertNull(this.observation, "Request state must not be reused by another invocation");
            this.observation = observation;
            observation.requestStateId = this.id;
            observation.vertxContext = Vertx.currentContext();
            observation.worker = Thread.currentThread();
        }

        Observation observation() {
            return this.observation;
        }

        void visit(String stage) {
            assertTrue(Arc.container().requestContext().isActive());
            assertFalse(Context.isOnEventLoopThread());
            assertTrue(BlockingOperationControl.isBlockingAllowed());
            assertTrue(VertxContext.isDuplicatedContext(Vertx.currentContext()));
            assertEquals(this.observation.requestStateId, this.id);
            assertSame(this.observation.vertxContext, Vertx.currentContext());
            assertSame(this.observation.worker, Thread.currentThread());
            assertEquals(0, this.observation.destructions.get());
            this.observation.visits.add(stage);
        }

        @PreDestroy
        void destroy() {
            if (this.observation != null) {
                this.observation.destructions.incrementAndGet();
                this.observation.destroyed.complete(null);
            }
        }
    }

    @Singleton
    public static class ProbeValidatorProducer implements ClientCredentialsRequestValidator {
        @Inject
        Observations observations;

        @Inject
        RequestState state;

        @Override
        public void validate(ClientCredentialsRequestContext context) {
            Observation observation = this.observations.requests.get(
                    context.request().getAdditionalParameters().get("probe_id"));
            state.attach(observation);
            state.visit("validator");
            observation.awaitRelease("validator");
            if ("validator".equals(observation.failingStage)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
        }
    }

    @Singleton
    public static class ProbeCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
        @Inject
        io.vertx.ext.web.RoutingContext routingContext;
        @Inject
        Observations observations;
        @Inject
        RequestState state;

        @Override
        public void customize(JwtEncodingContext context) {
            TokenGrantRequest grant = context.getAuthorizationGrant();
            Observation observation = this.observations.requests.get(grant.getAdditionalParameters().get("probe_id"));
            try {
                this.state.visit("customizer");
                assertEquals(
                        observation.id,
                        this.routingContext.request().formAttributes().get("probe_id"));
                if (observation.observeDisconnect) {
                    var routingContext = this.routingContext;
                    routingContext
                            .response()
                            .closeHandler(ignored -> observation.disconnected.complete(null));
                }
                observation.entered.complete(null);
                observation.awaitRelease("customizer");
                if ("customizer".equals(observation.failingStage)) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
                }
            } catch (RuntimeException | Error failure) {
                observation.failure = failure;
                throw failure;
            }
        }
    }

    @Singleton
    public static class ProbeAuthorizationService implements OAuth2AuthorizationService {
        private final InMemoryOAuth2AuthorizationService delegate = new InMemoryOAuth2AuthorizationService();
        @Inject
        RequestState state;

        @Override
        public void save(OAuth2Authorization authorization) {
            this.state.visit("save");
            Observation observation = this.state.observation();
            if ("save".equals(observation.failingStage)) {
                throw new IllegalStateException("Simulated storage failure");
            }
            this.delegate.save(authorization);
            observation.saved = authorization;
        }

        @Override
        public void remove(OAuth2Authorization authorization) {
            this.delegate.remove(authorization);
        }

        @Override
        public OAuth2Authorization findById(String id) {
            return this.delegate.findById(id);
        }

        @Override
        public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
            return this.delegate.findByToken(token, tokenType);
        }
    }
}
