package io.quarkiverse.authorization.server.it.multipleissuers;

import static org.junit.jupiter.api.Assertions.*;

import javax.sql.DataSource;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;

@QuarkusTest
@TestProfile(MultipleIssuersProfile.class)
class MultipleIssuersStorageTest {
    @Inject
    @io.quarkus.agroal.DataSource("alpha")
    DataSource alpha;
    @Inject
    @io.quarkus.agroal.DataSource("beta")
    DataSource beta;

    @Test
    void freshRepositoriesFindOnlyTheirOwnClientsAndAuthorizations() {
        var alphaClients = new JdbcRegisteredClientRepository(this.alpha);
        var betaClients = new JdbcRegisteredClientRepository(this.beta);
        var alphaClient = alphaClients.findByClientId("shared");
        var betaClient = betaClients.findByClientId("shared");
        assertEquals(alphaClient.getId(), betaClient.getId());
        assertTrue(BcryptUtil.matches("alpha-secret", alphaClient.getClientSecret()));
        assertFalse(BcryptUtil.matches("alpha-secret", betaClient.getClientSecret()));
        String token = MultipleIssuersHttpTest.request().auth().preemptive().basic("shared", "alpha-secret")
                .formParam("grant_type", "client_credentials")
                .formParam("scope", "alpha").post("/alpha/token").then().statusCode(200).extract().path("access_token");
        var alphaAuthorizations = new JdbcOAuth2AuthorizationService(this.alpha, alphaClients);
        var betaAuthorizations = new JdbcOAuth2AuthorizationService(this.beta, betaClients);
        var stored = alphaAuthorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        assertNotNull(stored);
        assertNull(betaAuthorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN));
        assertNull(betaAuthorizations.findById(stored.getId()));
        String uri = MultipleIssuersHttpTest.request().auth().preemptive().basic("shared", "alpha-secret")
                .formParam("response_type", "code")
                .formParam("client_id", "shared")
                .formParam("redirect_uri", MultipleIssuersHttpTest.REDIRECT).formParam("scope", "alpha")
                .formParam("code_challenge", MultipleIssuersHttpTest.CHALLENGE).formParam("code_challenge_method", "S256")
                .post("/alpha/oauth2/par").then().statusCode(201).extract().path("request_uri");
        String id = uri.substring(uri.lastIndexOf(':') + 1);
        assertNotNull(alphaAuthorizations.findById(id));
        assertNull(betaAuthorizations.findById(id));
    }
}
