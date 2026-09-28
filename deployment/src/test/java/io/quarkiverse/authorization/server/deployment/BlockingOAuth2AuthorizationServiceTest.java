package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Context;

class BlockingOAuth2AuthorizationServiceTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar
                    .addClasses(ResourceOwnerIdentityProvider.class, RecordingOAuth2AuthorizationService.class)
                    .addAsResource("privateKey.pem")
                    .addAsResource("publicKey.pem")
                    .addAsResource(
                            new StringAsset(
                                    """
                                            quarkus.authorization-server.issuer=https://issuer.example.com
                                            quarkus.authorization-server.signing.key-id=test-key
                                            quarkus.authorization-server.signing.private-key-location=classpath:privateKey.pem
                                            quarkus.authorization-server.signing.public-key-location=classpath:publicKey.pem
                                            quarkus.authorization-server.clients.jdbc-client.client-secret=$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK
                                            quarkus.authorization-server.clients.jdbc-client.authorization-grant-types=password
                                            quarkus.authorization-server.clients.jdbc-client.scopes=message.read
                                            """),
                            "application.properties"));

    @BeforeEach
    void resetService() {
        RecordingOAuth2AuthorizationService.authorizations.clear();
        RecordingOAuth2AuthorizationService.invokedOnEventLoop = false;
        RecordingOAuth2AuthorizationService.failSave = false;
    }

    @Test
    void authorizationSaveIsOffloadedAndCompletesBeforeResponse() {
        String accessToken = tokenRequest()
                .then()
                .statusCode(200)
                .body("access_token", notNullValue())
                .extract().path("access_token");

        assertFalse(RecordingOAuth2AuthorizationService.invokedOnEventLoop,
                "OAuth2AuthorizationService must not execute on the Vert.x event-loop thread");
        assertNotNull(RecordingOAuth2AuthorizationService.find(accessToken));
    }

    @Test
    void saveFailureDoesNotReturnIssuedAccessToken() {
        RecordingOAuth2AuthorizationService.failSave = true;

        tokenRequest()
                .then()
                .statusCode(400)
                .body("error", equalTo("server_error"))
                .body("$", not(hasKey("access_token")));
    }

    @Test
    void revocationSaveFailureReturnsServerErrorFromWorker() {
        String accessToken = tokenRequest().then().statusCode(200).extract().path("access_token");
        RecordingOAuth2AuthorizationService.invokedOnEventLoop = true;
        RecordingOAuth2AuthorizationService.failSave = true;

        given().auth().preemptive().basic("jdbc-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("token", accessToken)
                .post("/oauth2/revoke")
                .then().statusCode(400)
                .body("error", equalTo("server_error"))
                .body("$", not(hasKey("access_token")));

        assertFalse(RecordingOAuth2AuthorizationService.invokedOnEventLoop,
                "Revocation persistence must not execute on the Vert.x event-loop thread");
    }

    private static io.restassured.response.Response tokenRequest() {
        return given()
                .auth().preemptive().basic("jdbc-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password")
                .when().post("/oauth2/token");
    }

    @Singleton
    public static class RecordingOAuth2AuthorizationService implements OAuth2AuthorizationService {

        static final Map<String, OAuth2Authorization> authorizations = new ConcurrentHashMap<>();
        static volatile boolean invokedOnEventLoop;
        static volatile boolean failSave;

        @Override
        public void save(OAuth2Authorization authorization) {
            invokedOnEventLoop = Context.isOnEventLoopThread();
            if (failSave) {
                throw new IllegalStateException("simulated JDBC failure");
            }
            authorizations.put(authorization.getId(), authorization);
        }

        @Override
        public void remove(OAuth2Authorization authorization) {
            authorizations.remove(authorization.getId());
        }

        @Override
        public OAuth2Authorization findById(String id) {
            return authorizations.get(id);
        }

        @Override
        public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
            return find(token);
        }

        static OAuth2Authorization find(String token) {
            return authorizations.values().stream()
                    .filter(authorization -> authorization.getToken(token) != null)
                    .findFirst()
                    .orElse(null);
        }
    }

    @Singleton
    public static class ResourceOwnerIdentityProvider implements IdentityProvider<UsernamePasswordAuthenticationRequest> {

        @Override
        public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
            return UsernamePasswordAuthenticationRequest.class;
        }

        @Override
        public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
                AuthenticationRequestContext context) {
            if (!"resource-owner".equals(request.getUsername())
                    || !Arrays.equals("resource-owner-password".toCharArray(), request.getPassword().getPassword())) {
                return Uni.createFrom().failure(new AuthenticationFailedException());
            }
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal(request.getUsername()))
                    .build());
        }
    }
}
