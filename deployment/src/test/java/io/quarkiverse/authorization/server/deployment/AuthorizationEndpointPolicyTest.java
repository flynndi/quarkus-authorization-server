package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeGenerator;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentContext;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentCustomizer;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentPolicy;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestContext;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestValidator;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceCodeGenerator;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceConsentCustomizer;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceConsentPolicy;
import io.quarkiverse.authorization.server.grant.devicecode.UserCodeGenerator;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.DefaultAuthorizationConsentPolicy;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DefaultDeviceConsentPolicy;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.OAuth2UserCodeGenerator;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.arc.Arc;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

class AuthorizationEndpointPolicyTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addClasses(
                            ResourceOwnerAuthenticationMechanism.class,
                            Policies.class,
                            CodePolicies.class,
                            ObserveCodePolicy.class,
                            CodePolicyInterceptor.class,
                            PolicyRequestProbe.class,
                            PolicyRequestProbe.Observations.class)
                            .addAsResource(
                                    new StringAsset(
                                            """
                                                    quarkus.authorization-server.issuer=https://issuer.example
                                                    quarkus.authorization-server.clients.policy.client-secret=$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK
                                                    quarkus.authorization-server.clients.policy.authorization-grant-types=authorization_code,urn:ietf:params:oauth:grant-type:device_code
                                                    quarkus.authorization-server.clients.policy.redirect-uris=https://client.example/callback
                                                    quarkus.authorization-server.clients.policy.scopes=message.read,openid
                                                    quarkus.authorization-server.clients.public.client-authentication-methods=none
                                                    quarkus.authorization-server.clients.public.authorization-grant-types=authorization_code
                                                    quarkus.authorization-server.clients.public.redirect-uris=https://client.example/callback
                                                    quarkus.authorization-server.clients.public.scopes=message.read
                                                    quarkus.authorization-server.clients.wrong-grant.client-secret=unused
                                                    quarkus.authorization-server.clients.wrong-grant.authorization-grant-types=client_credentials
                                                    quarkus.authorization-server.clients.wrong-grant.redirect-uris=https://client.example/callback
                                                    quarkus.authorization-server.clients.wrong-grant.scopes=message.read
                                                    """),
                                    "application.properties"));

    @Inject
    CodePolicies policies;
    @Inject
    PolicyRequestProbe.Observations observations;
    @Inject
    OAuth2AuthorizationService authorizations;
    @Inject
    OAuth2AuthorizationConsentService consents;
    @Inject
    RegisteredClientRepository clients;

    @org.junit.jupiter.api.BeforeEach
    void clearObservations() {
        this.observations.clear();
        this.policies.validatorInvocations.set(0);
        this.policies.interceptions.set(0);
    }

    @Test
    void applicationValidatorControlsHttpAndReleasesItsRequestScopeOnFailure() {
        authorization("policy", "deny")
                .get("/oauth2/authorize")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_request"));
        this.observations.assertReleased(List.of("code-validator"));
        authorization("policy", "normal")
                .queryParam("scope", "unregistered")
                .get("/oauth2/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString("error=invalid_scope"));
    }

    @Test
    void fixedGrantAndPkceChecksRunBeforeApplicationValidation() {
        var missingChallenge = (io.restassured.specification.FilterableRequestSpecification) authorization("public", "relax");
        missingChallenge.removeQueryParam("code_challenge");
        missingChallenge
                .get("/oauth2/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString("error=invalid_request"));
        authorization("wrong-grant", "relax")
                .get("/oauth2/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString("error=unauthorized_client"));
        assertEquals(0, this.policies.validatorInvocations.get());
    }

    @Test
    void applicationValidatorCannotBypassRedirectScopeOrDisabledOidcChecks() {
        authorization("policy", "relax")
                .queryParam("redirect_uri", "https://attacker.example/callback")
                .get("/oauth2/authorize")
                .then()
                .statusCode(400)
                .header("Location", org.hamcrest.Matchers.nullValue());
        authorization("policy", "relax")
                .queryParam("scope", "unregistered")
                .get("/oauth2/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString("error=invalid_scope"));
        authorization("policy", "relax")
                .queryParam("scope", "openid")
                .get("/oauth2/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString("error=invalid_scope"));
        assertEquals(0, this.policies.validatorInvocations.get());
    }

    @Test
    void sameGeneratorServesImmediateIssuanceAndCustomizedConsent() {
        int before = this.policies.codeGenerations.get();
        Response immediate = authorization("policy", "normal").get("/oauth2/authorize");
        immediate.then().statusCode(302).header("Location", containsString("code=policy-code-"));
        String owner = "consent-" + UUID.randomUUID();
        Response page = authorization("policy", "force", owner)
                .queryParam("scope", "message.read")
                .get("/oauth2/authorize");
        page.then().statusCode(200).body(containsString("message.read"));
        given().header("user", owner)
                .redirects()
                .follow(false)
                .contentType(ContentType.URLENC)
                .formParam("client_id", "policy")
                .formParam("state", hidden(page, "state"))
                .formParam("scope", "message.read")
                .post("/oauth2/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString("code=policy-code-"));
        assertEquals(before + 2, this.policies.codeGenerations.get());
        assertTrue(
                this.consents
                        .findById(this.clients.findByClientId("policy").getId(), owner)
                        .getAuthorities()
                        .contains("code:policy"));
        this.observations.assertReleased(
                List.of("code-validator", "code-predicate", "code-generator"));
        this.observations.assertReleased(List.of("code-consent", "code-generator"));
    }

    @Test
    void denialInvokesApplicationCustomizerAndPreservesConsentWithoutSavingCandidateChanges() {
        String owner = "denial-" + UUID.randomUUID();
        var client = this.clients.findByClientId("policy");
        var previous = OAuth2AuthorizationConsent.withId(client.getId(), owner).scope("message.read").build();
        this.consents.save(previous);
        Response page = AuthorizationEndpointPolicyTest.authorization("policy", "force", owner)
                .queryParam("scope", "message.read").get("/oauth2/authorize");
        String state = AuthorizationEndpointPolicyTest.hidden(page, "state");
        var pending = this.authorizations.findByToken(state, new OAuth2TokenType("state"));
        int generated = this.policies.codeGenerations.get();

        given().header("user", owner).redirects().follow(false).contentType(ContentType.URLENC)
                .formParam("client_id", "policy").formParam("state", state)
                .formParam("scope", "message.read").formParam("consent_action", "deny")
                .post("/oauth2/authorize").then().statusCode(302)
                .header("Location", containsString("error=access_denied"));

        Assertions.assertNull(this.authorizations.findById(pending.getId()));
        Assertions.assertEquals(previous, this.consents.findById(client.getId(), owner));
        Assertions.assertEquals(generated, this.policies.codeGenerations.get());
        this.observations.assertReleased(List.of("code-consent"));
    }

    @ParameterizedTest
    @ValueSource(strings = { "APPROVE", "DENY" })
    void applicationCustomizerControlsFinalDecisionThroughCdi(String decisionName) {
        var decision = AuthorizationConsentContext.Decision.valueOf(decisionName);
        String owner = "decision-" + UUID.randomUUID();
        Response page = AuthorizationEndpointPolicyTest.authorization("policy", "force", owner)
                .queryParam("scope", "message.read").get("/oauth2/authorize");
        boolean approve = decision == AuthorizationConsentContext.Decision.APPROVE;

        given().header("user", owner).redirects().follow(false).contentType(ContentType.URLENC)
                .formParam("client_id", "policy").formParam("state", AuthorizationEndpointPolicyTest.hidden(page, "state"))
                .formParam("scope", "message.read").formParam("consent_action", approve ? "deny" : "approve")
                .formParam("test_decision", decision.name())
                .post("/oauth2/authorize").then().statusCode(302)
                .header("Location", containsString(approve ? "code=policy-code-" : "error=access_denied"));

        this.observations.assertReleased(approve ? List.of("code-consent", "code-generator") : List.of("code-consent"));
    }

    @Test
    void directlyImplementedPolicySpisRetainCdiInterceptionAndRequestScope() {
        authorization("policy", "normal", "intercepted-" + UUID.randomUUID())
                .get("/oauth2/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString("code=policy-code-"));
        assertEquals(3, this.policies.interceptions.get());
        this.observations.assertReleased(
                List.of("code-validator", "code-predicate", "code-generator"));
    }

    @Test
    void deviceGeneratorsPredicateAndConsentPolicyControlTheirOwnEndpoints() {
        Response device = issue();
        device.then().body("device_code", containsString("policy-device-"));
        String userCode = device.path("user_code");
        String owner = "device-" + UUID.randomUUID();
        Response page = given().header("user", owner)
                .queryParam("user_code", userCode)
                .get("/oauth2/device_verification");
        page.then().statusCode(200).body(containsString("Confirm your device"));
        given().header("user", owner)
                .cookies(page.cookies())
                .contentType(ContentType.URLENC)
                .formParam("client_id", "policy")
                .formParam("user_code", userCode)
                .formParam("state", hidden(page, "state"))
                .formParam("approved", true)
                .formParam("scope", "message.read")
                .post("/oauth2/device_verification")
                .then()
                .statusCode(200)
                .body(containsString("Device authorized"));
        var consent = this.consents.findById(this.clients.findByClientId("policy").getId(), owner);
        assertEquals(Set.of("SCOPE_message.read", "device:policy"), consent.getAuthorities());
        this.observations.assertReleased(List.of("device-generator", "user-generator"));
        this.observations.assertReleased(List.of("device-predicate"));
        this.observations.assertReleased(List.of("device-consent"));
    }

    @Test
    void deviceConsentPredicateSkipsScopeSelectionButStillRequiresDeviceConfirmation() {
        Response device = issue();
        String owner = "skip-" + UUID.randomUUID();
        Response page = given().header("user", owner)
                .queryParam("user_code", device.<String> path("user_code"))
                .get("/oauth2/device_verification")
                .then()
                .statusCode(200)
                .body(containsString("Confirm your device"))
                .extract()
                .response();
        var pending = this.authorizations.findByToken(
                device.path("device_code"), new OAuth2TokenType("device_code"));
        assertNotNull(pending);
        assertTrue(
                pending.getToken(
                        io.quarkiverse.authorization.server.token.OAuth2UserCode.class)
                        .isActive());
        assertFalse(page.asString().contains("name=\"scope\""));
        given().header("user", owner)
                .contentType(ContentType.URLENC)
                .formParam("client_id", "policy")
                .formParam("user_code", device.<String> path("user_code"))
                .formParam("state", hidden(page, "state"))
                .formParam("approved", true)
                .post("/oauth2/device_verification")
                .then()
                .statusCode(200)
                .body(containsString("Device authorized"));
        var authorization = this.authorizations.findByToken(
                device.path("device_code"), new OAuth2TokenType("device_code"));
        assertEquals(Set.of("message.read"), authorization.getAuthorizedScopes());
        this.observations.assertReleased(List.of("device-predicate"));
        this.observations.assertReleased(List.of("device-consent"));
    }

    private static RequestSpecification authorization(String client, String state) {
        return authorization(client, state, "owner");
    }

    private static RequestSpecification authorization(String client, String state, String owner) {
        return given().redirects()
                .follow(false)
                .header("user", owner)
                .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .queryParam("code_challenge_method", "S256")
                .queryParam("response_type", "code")
                .queryParam("client_id", client)
                .queryParam("redirect_uri", "https://client.example/callback")
                .queryParam("state", state);
    }

    private static Response issue() {
        return given().auth()
                .preemptive()
                .basic("policy", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("scope", "message.read")
                .post("/oauth2/device_authorization")
                .then()
                .statusCode(200)
                .extract()
                .response();
    }

    private static String hidden(Response page, String name) {
        var matcher = Pattern.compile("name=\"" + name + "\" value=\"([^\"]+)\"")
                .matcher(page.asString());
        assertTrue(matcher.find(), page.asString());
        return matcher.group(1);
    }

    @jakarta.interceptor.InterceptorBinding
    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
    @java.lang.annotation.Target({
            java.lang.annotation.ElementType.TYPE,
            java.lang.annotation.ElementType.METHOD
    })
    public @interface ObserveCodePolicy {
    }

    @ObserveCodePolicy
    @jakarta.interceptor.Interceptor
    @Priority(jakarta.interceptor.Interceptor.Priority.APPLICATION)
    public static class CodePolicyInterceptor {
        @jakarta.interceptor.AroundInvoke
        Object observe(jakarta.interceptor.InvocationContext invocation) throws Exception {
            assertTrue(Arc.container().requestContext().isActive());
            assertTrue(io.quarkus.runtime.BlockingOperationControl.isBlockingAllowed());
            ((CodePolicies) invocation.getTarget()).interceptions.incrementAndGet();
            return invocation.proceed();
        }
    }

    @Singleton
    @ObserveCodePolicy
    public static class CodePolicies
            implements AuthorizationRequestValidator,
            AuthorizationConsentPolicy,
            AuthorizationCodeGenerator,
            AuthorizationConsentCustomizer {
        @Inject
        PolicyRequestProbe request;
        final AtomicInteger codeGenerations = new AtomicInteger();
        final AtomicInteger validatorInvocations = new AtomicInteger();
        final AtomicInteger interceptions = new AtomicInteger();

        @Override
        public void validate(AuthorizationRequestContext context) {
            this.validatorInvocations.incrementAndGet();
            this.request.visit("code-validator");
            if ("deny".equals(context.getRequest().getState())) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
        }

        @Override
        public boolean isConsentRequired(AuthorizationRequestContext context) {
            this.request.visit("code-predicate");
            assertNotNull(context.getAuthorizationRequest());
            return "force".equals(context.getRequest().getState())
                    || new DefaultAuthorizationConsentPolicy().isConsentRequired(context);
        }

        @Override
        public OAuth2AuthorizationCode generate(OAuth2TokenContext context) {
            this.request.visit("code-generator");
            return new OAuth2AuthorizationCode(
                    "policy-code-" + this.codeGenerations.incrementAndGet(),
                    Instant.now(),
                    Instant.now().plusSeconds(60));
        }

        @Override
        public void customize(AuthorizationConsentContext context) {
            this.request.visit("code-consent");
            context.getAuthorizationConsent().authority("code:policy");
            // Test-only application policy, exercising both decisions through the actual CDI hook.
            String decision = (String) context.getSubmission().getAdditionalParameters().get("test_decision");
            if (decision != null) {
                context.setDecision(AuthorizationConsentContext.Decision.valueOf(decision));
            }
        }
    }

    @Singleton
    public static class Policies {

        @Inject
        PolicyRequestProbe request;
        @Inject
        RoutingContext http;

        @jakarta.enterprise.inject.Produces
        @Singleton
        DeviceCodeGenerator deviceGenerator() {
            return context -> {
                this.request.visit("device-generator");
                assertEquals("/oauth2/device_authorization", this.http.request().path());
                return new OAuth2DeviceCode(
                        "policy-device-" + UUID.randomUUID(),
                        Instant.now(),
                        Instant.now().plusSeconds(60));
            };
        }

        @jakarta.enterprise.inject.Produces
        @Singleton
        UserCodeGenerator userGenerator() {
            return context -> {
                this.request.visit("user-generator");
                assertEquals("/oauth2/device_authorization", this.http.request().path());
                return new OAuth2UserCodeGenerator().generate(context);
            };
        }

        @jakarta.enterprise.inject.Produces
        @Singleton
        DeviceConsentPolicy deviceConsentRequired() {
            return context -> {
                this.request.visit("device-predicate");
                assertEquals("/oauth2/device_verification", this.http.request().path());
                return !context.request()
                        .getPrincipal()
                        .getPrincipal()
                        .getName()
                        .startsWith("skip-")
                        && new DefaultDeviceConsentPolicy().isConsentRequired(context);
            };
        }

        @jakarta.enterprise.inject.Produces
        @Singleton
        DeviceConsentCustomizer deviceConsent() {
            return context -> {
                this.request.visit("device-consent");
                assertEquals("/oauth2/device_verification", this.http.request().path());
                context.authorizationConsent().authority("device:policy");
            };
        }
    }

    @ApplicationScoped
    public static class ResourceOwnerAuthenticationMechanism
            implements HttpAuthenticationMechanism {

        @Override
        public Uni<SecurityIdentity> authenticate(
                RoutingContext context, IdentityProviderManager identityProviderManager) {
            String principalName = context.request().getHeader("user");
            if (principalName == null) {
                return Uni.createFrom().nullItem();
            }
            return Uni.createFrom()
                    .item(
                            QuarkusSecurityIdentity.builder()
                                    .setPrincipal(new QuarkusPrincipal(principalName))
                                    .build());
        }

        @Override
        public Uni<ChallengeData> getChallenge(RoutingContext context) {
            return Uni.createFrom().nullItem();
        }

        @Override
        public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
            return Collections.emptySet();
        }

        @Override
        public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
            return Uni.createFrom().nullItem();
        }
    }
}
