package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;

import java.lang.annotation.*;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.annotation.PreDestroy;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InterceptorBinding;
import jakarta.interceptor.InvocationContext;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentPolicy;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestContext;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequestContext;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequestValidator;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.metadata.AuthorizationServerMetadataCustomizer;
import io.quarkiverse.authorization.server.token.AuthorizationServerKeySource;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenClaimsContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.arc.Arc;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.smallrye.jwt.util.KeyUtils;

class AuthorizationServerCdiCompositionTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addClasses(NativeImageResourceAssertions.class,
                            NativeImageResourceAssertions.ResourcesVerifiedBuildItem.class).addClasses(
                                    First.class,
                                    AuxiliaryValidator.class,
                                    Last.class,
                                    DirectValidator.class,
                                    OtherValidator.class,
                                    Consent.class,
                                    ApplicationKeys.class,
                                    PolicyRequestProbe.class,
                                    PolicyRequestProbe.Observations.class,
                                    Traced.class,
                                    TraceInterceptor.class,
                                    Calls.class)
                            .addAsResource(
                                    new StringAsset(
                                            """
                                                    quarkus.authorization-server.issuer=https://issuer.example
                                                    quarkus.authorization-server.signing.private-key-location=classpath:must-not-be-read.pem
                                                    quarkus.authorization-server.clients.machine.client-secret=$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK
                                                    quarkus.authorization-server.clients.machine.authorization-grant-types=client_credentials
                                                    quarkus.authorization-server.clients.machine.scopes=read
                                                    quarkus.authorization-server.clients.reference.client-secret=%s
                                                    quarkus.authorization-server.clients.reference.authorization-grant-types=client_credentials
                                                    quarkus.authorization-server.clients.reference.scopes=read
                                                    quarkus.authorization-server.clients.reference.access-token-format=reference
                                                    """
                                                    .formatted(
                                                            io.quarkus.elytron.security.common.BcryptUtil
                                                                    .bcryptHash(
                                                                            "client-secret"))),
                                    "application.properties"))
            .addBuildChainCustomizer(NativeImageResourceAssertions.verify(Set.of(), Set.of("must-not-be-read.pem")));

    @Inject
    Calls calls;
    @Inject
    PolicyRequestProbe.Observations observations;
    @Inject
    OAuth2AuthorizationService authorizations;

    @Test
    void runsCdiPoliciesInArcPriorityOrderWithRequestScopeAndInterceptors() {
        this.observations.clear();
        int intercepted = this.calls.intercepted.get();
        for (String client : List.of("machine", "reference")) {
            String access = given().auth()
                    .preemptive()
                    .basic(client, "client-secret")
                    .contentType(ContentType.URLENC)
                    .formParam("grant_type", "client_credentials")
                    .formParam("scope", "read")
                    .post("/oauth2/token")
                    .then()
                    .statusCode(200)
                    .extract()
                    .path("access_token");
            var token = this.authorizations
                    .findByToken(access, OAuth2TokenType.ACCESS_TOKEN)
                    .getAccessToken();
            assertEquals("CDI", token.getClaims().get("configured"));
        }
        assertEquals(intercepted + 2, this.calls.intercepted.get());
        this.observations.assertReleased(List.of("first", "direct", "other", "last", "claims"));
        assertEquals(2, this.observations.visits.size());
    }

    @Test
    void metadataUsesRequestContextAndApplicationKeySourceOverridesDefaultLoading() {
        this.observations.clear();
        given().get("/.well-known/oauth-authorization-server")
                .then()
                .statusCode(200)
                .body("configured", equalTo("CDI"));
        this.observations.assertReleased(List.of("metadata"));
        given().get("/oauth2/jwks")
                .then()
                .statusCode(200)
                .body("keys[0].kid", equalTo("application-key"));
    }

    @Test
    void mandatoryValidationStillRunsBeforeApplicationPolicies() {
        this.observations.clear();
        given().auth()
                .preemptive()
                .basic("machine", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials")
                .formParam("scope", "admin")
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_scope"));
        assertTrue(this.observations.visits.isEmpty());
    }

    @Singleton
    @Priority(30)
    public static class First implements ClientCredentialsRequestValidator {
        @Inject
        PolicyRequestProbe request;

        public void validate(ClientCredentialsRequestContext context) {
            request.visit("first");
        }

        @jakarta.enterprise.inject.Produces
        @Singleton
        OAuth2TokenCustomizer<JwtEncodingContext> jwtClaims() {
            return context -> {
                request.visit("claims");
                context.getClaims().claim("configured", "CDI");
            };
        }

        @jakarta.enterprise.inject.Produces
        @Singleton
        OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessClaims() {
            return context -> {
                request.visit("claims");
                context.getClaims().claim("configured", "CDI");
            };
        }

        @jakarta.enterprise.inject.Produces
        @Singleton
        AuthorizationServerMetadataCustomizer metadata() {
            return metadata -> {
                request.visit("metadata");
                metadata.claim("configured", "CDI");
            };
        }
    }

    @jakarta.enterprise.context.Dependent
    public static class Last implements ClientCredentialsRequestValidator {
        private boolean destroyed;

        @PreDestroy
        void destroy() {
            destroyed = true;
        }

        @Inject
        PolicyRequestProbe request;

        public void validate(ClientCredentialsRequestContext context) {
            assertFalse(destroyed);
            request.visit("last");
        }
    }

    // Auxiliary qualified beans do not implicitly join the default protocol chain.
    @Singleton
    @io.smallrye.common.annotation.Identifier("auxiliary")
    public static class AuxiliaryValidator implements ClientCredentialsRequestValidator {
        public void validate(ClientCredentialsRequestContext context) {
            fail("Auxiliary validator must not join the default chain");
        }
    }

    @RequestScoped
    @Priority(20)
    public static class DirectValidator implements ClientCredentialsRequestValidator {
        @Inject
        PolicyRequestProbe request;

        @Traced
        public void validate(ClientCredentialsRequestContext context) {
            request.visit("direct");
        }
    }

    @RequestScoped
    @Priority(10)
    public static class OtherValidator implements ClientCredentialsRequestValidator {
        @Inject
        PolicyRequestProbe request;

        public void validate(ClientCredentialsRequestContext context) {
            request.visit("other");
        }
    }

    @RequestScoped
    public static class Consent implements AuthorizationConsentPolicy {
        public boolean isConsentRequired(AuthorizationRequestContext context) {
            return false;
        }
    }

    @Singleton
    public static class ApplicationKeys implements AuthorizationServerKeySource {
        public KeySet load() {
            try {
                var pair = KeyUtils.generateKeyPair(2048);
                return new KeySet(
                        List.of(
                                new Key(
                                        "application-key",
                                        SignatureAlgorithm.RS256,
                                        pair.getPrivate(),
                                        pair.getPublic())),
                        "application-key");
            } catch (Exception failure) {
                throw new IllegalStateException(failure);
            }
        }
    }

    @InterceptorBinding
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.METHOD, ElementType.TYPE })
    public @interface Traced {
    }

    @Traced
    @Interceptor
    @Priority(1)
    public static class TraceInterceptor {
        @Inject
        Calls calls;

        @AroundInvoke
        Object invoke(InvocationContext context) throws Exception {
            assertTrue(Arc.container().requestContext().isActive());
            calls.intercepted.incrementAndGet();
            return context.proceed();
        }
    }

    @Singleton
    public static class Calls {
        final AtomicInteger intercepted = new AtomicInteger();
    }
}
