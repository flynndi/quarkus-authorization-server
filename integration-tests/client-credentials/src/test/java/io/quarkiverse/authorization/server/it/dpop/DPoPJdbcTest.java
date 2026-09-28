package io.quarkiverse.authorization.server.it.dpop;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.*;

import jakarta.inject.Inject;

import org.jose4j.jwk.JsonWebKey;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.it.common.dpop.client.DPoPClient;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.introspection.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.introspection.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import io.quarkus.security.runtime.*;
import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
class DPoPJdbcTest {
    @Inject
    OAuth2AuthorizationService authorizations;
    @Inject
    RegisteredClientRepository clients;

    @Test
    void fixtureClaimsSurviveJdbcAndIntrospection() throws Exception {
        var key = DPoPClient.key();
        var tokens = given().contentType("application/json")
                .body(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY))
                .post("/fixture/tokens")
                .then()
                .statusCode(200)
                .extract()
                .response();
        var principal = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("dpop-resource-server"))
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                        clients.findByClientId("dpop-resource-server"))
                .build();
        var introspector = new OAuth2TokenIntrospectionAuthenticationProvider(clients, authorizations);
        for (String format : java.util.List.of("jwt", "opaque")) {
            var response = introspector.authenticate(
                    new OAuth2TokenIntrospectionAuthenticationToken(
                            tokens.path(format), principal, null, java.util.Map.of()));
            assertTrue(response.getTokenClaims().isActive());
            assertEquals("DPoP", response.getTokenClaims().getTokenType());
            assertEquals(
                    java.util.Map.of("jkt", DPoPClient.thumbprint(key)),
                    response.getTokenClaims().getClaims().get("cnf"));
        }
    }
}
