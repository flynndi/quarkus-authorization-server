package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.smallrye.mutiny.Uni;

class DefaultSigningKeyTest {

    private static final String CLIENT_SECRET_HASH = "$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar
                    .addClass(ResourceOwnerIdentityProvider.class)
                    .addAsResource(new StringAsset("""
                            quarkus.http.auth.basic=true
                            quarkus.authorization-server.issuer=https://issuer.example.com
                            quarkus.authorization-server.clients.default-client.client-secret=%s
                            quarkus.authorization-server.clients.default-client.authorization-grant-types=password
                            quarkus.authorization-server.clients.default-client.scopes=message.read
                            """.formatted(CLIENT_SECRET_HASH)), "application.properties"));

    @Inject
    AuthorizationServerKeyManager keyManager;

    @Test
    void generatesDefaultRsaKeyForJwtAndJwks() {
        assertEquals(SignatureAlgorithm.RS256, this.keyManager.getAlgorithm());

        given()
                .auth().preemptive().basic("default-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password")
                .when().post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("access_token", matchesPattern("^[^.]+\\.[^.]+\\.[^.]+$"));

        given()
                .when().get("/oauth2/jwks")
                .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("keys[0].kty", equalTo("RSA"))
                .body("keys[0].alg", equalTo("RS256"))
                .body("keys[0].kid", notNullValue());
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
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal(request.getUsername()))
                    .build());
        }
    }
}
