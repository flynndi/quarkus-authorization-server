package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.concurrent.atomic.AtomicInteger;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequestContext;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequestValidator;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.specification.RequestSpecification;

class OAuth2ClientCredentialsValidatorTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addAsResource("privateKey.pem")
                            .addAsResource("publicKey.pem")
                            .addClass(ApplicationValidators.class)
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
    ApplicationValidators validators;
    @Inject
    OAuth2AuthorizationService authorizations;

    @Test
    void applicationValidatorControlsTheActualTokenEndpoint() {
        int calls = this.validators.calls.get();
        tokenRequest()
                .formParam("scope", "message.read")
                .formParam("deny", "true")
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_request"));
        assertEquals(calls + 1, this.validators.calls.get());

        String accessToken = tokenRequest()
                .formParam("scope", "message.read")
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("scope", equalTo("message.read"))
                .extract()
                .path("access_token");
        assertEquals(calls + 2, this.validators.calls.get());
        assertNotNull(this.authorizations.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN));
    }

    @Test
    void applicationValidatorCannotBypassMandatoryScopeValidation() {
        int calls = this.validators.calls.get();
        tokenRequest()
                .formParam("scope", "message.admin")
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_scope"));
        assertEquals(calls, this.validators.calls.get());
    }

    private static RequestSpecification tokenRequest() {
        return given().auth()
                .preemptive()
                .basic("machine", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials");
    }

    @Singleton
    public static class ApplicationValidators implements ClientCredentialsRequestValidator {
        final AtomicInteger calls = new AtomicInteger();

        @Override
        public void validate(ClientCredentialsRequestContext context) {
            this.calls.incrementAndGet();
            if ("true".equals(context.request().getAdditionalParameters().get("deny"))) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
        }
    }
}
