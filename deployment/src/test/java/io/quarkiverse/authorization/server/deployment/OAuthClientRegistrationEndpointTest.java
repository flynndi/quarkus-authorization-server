package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;

class OAuthClientRegistrationEndpointTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(OAuthClientRegistrationTestSupport::application)
            .overrideConfigKey("quarkus.authorization-server.oidc.enabled", "false")
            .overrideConfigKey("quarkus.authorization-server.oidc.client-registration.enabled", "false")
            .overrideConfigKey("quarkus.authorization-server.client-registration.enabled", "true")
            .overrideConfigKey("quarkus.authorization-server.client-registration-endpoint", "/oauth-clients");
    @Inject
    OAuth2AuthorizationService authorizations;
    @Inject
    RegisteredClientRepository clients;

    @ParameterizedTest
    @ValueSource(strings = { "client_secret_basic", "client_secret_post" })
    void registersMachineClientConsumesInitialTokenAndAuthenticatesAtTokenEndpoint(String method) {
        String initial = this.initial(Set.of("client.create"));
        var response = given().auth().oauth2(initial).contentType(ContentType.JSON)
                .body(Map.of("client_name", "machine", "token_endpoint_auth_method", method,
                        "grant_types", List.of("client_credentials"), "scope", "message.read"))
                .post("/oauth-clients").then().statusCode(201).header("Cache-Control", containsString("no-store"))
                .body("token_endpoint_auth_method", equalTo(method)).body("grant_types", contains("client_credentials"))
                .body("$", not(hasKey("redirect_uris"))).body("$", not(hasKey("response_types")))
                .body("$", not(hasKey("registration_access_token"))).body("$", not(hasKey("registration_client_uri")))
                .body("client_secret_expires_at", equalTo(0)).extract().response();
        String id = response.path("client_id"), secret = response.path("client_secret");
        assertTrue(BcryptUtil.matches(secret, this.clients.findByClientId(id).getClientSecret()));
        assertNotEquals(secret, this.clients.findByClientId(id).getClientSecret());
        var consumed = this.authorizations.findByToken(initial, OAuth2TokenType.ACCESS_TOKEN);
        assertFalse(consumed.getAccessToken().isActive());
        assertFalse(consumed.getRefreshToken().isActive());
        var token = given().formParam("grant_type", "client_credentials").formParam("scope", "message.read");
        if (method.equals("client_secret_basic"))
            token.auth().preemptive().basic(id, secret);
        else
            token.formParam("client_id", id).formParam("client_secret", secret);
        token.post("/oauth2/token").then().statusCode(200).body("access_token", notNullValue());
        given().auth().oauth2(initial).contentType(ContentType.JSON).body(Map.of("grant_types", List.of("client_credentials")))
                .post("/oauth-clients").then().statusCode(401);
    }

    @Test
    void publicRegistrationUsesCodeConsentAndPkceWithoutIssuingSecrets() {
        var registration = given().auth().oauth2(this.initial(Set.of("client.create"))).contentType(ContentType.JSON)
                .body(Map.of("redirect_uris", List.of("https://client.example/callback"), "token_endpoint_auth_method", "none",
                        "scope", "message.read"))
                .post("/oauth-clients").then().statusCode(201).body("$", not(hasKey("client_secret")))
                .body("$", not(hasKey("client_secret_expires_at"))).body("response_types", contains("code")).extract()
                .response();
        String client = registration.path("client_id");
        assertTrue(this.clients.findByClientId(client).getClientSettings().isRequireProofKey());
        assertTrue(this.clients.findByClientId(client).getClientSettings().isRequireAuthorizationConsent());
        var page = given().auth().preemptive().basic("owner", "password").redirects().follow(false)
                .queryParam("client_id", client).queryParam("response_type", "code")
                .queryParam("redirect_uri", "https://client.example/callback")
                .queryParam("scope", "message.read").queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .queryParam("code_challenge_method", "S256").get("/oauth2/authorize").then().statusCode(200).extract()
                .response();
        String state = page.htmlPath().getString("**.find { it.@name == 'state' }.@value");
        String location = given().auth().preemptive().basic("owner", "password").redirects().follow(false)
                .formParam("client_id", client).formParam("state", state).formParam("scope", "message.read")
                .formParam("consent_action", "approve")
                .post("/oauth2/authorize").then().statusCode(302).extract().header("Location");
        String code = java.util.Arrays.stream(URI.create(location).getRawQuery().split("&")).filter(x -> x.startsWith("code="))
                .map(x -> URLDecoder.decode(x.substring(5), StandardCharsets.UTF_8)).findFirst().orElseThrow();
        given().formParam("grant_type", "authorization_code").formParam("client_id", client).formParam("code", code)
                .formParam("redirect_uri", "https://client.example/callback")
                .formParam("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
                .post("/oauth2/token").then().statusCode(200).body("access_token", notNullValue())
                .body("$", not(hasKey("id_token")));
    }

    @Test
    void protectedRegistrationRequiresOnlyTheExactInitialScope() {
        given().contentType(ContentType.JSON).body("{}").post("/oauth-clients").then().statusCode(401);
        given().auth().preemptive().basic("owner", "password").contentType(ContentType.JSON).body("{}")
                .post("/oauth-clients").then().statusCode(401);
        for (var scopes : List.of(Set.of("message.read"), Set.of("client.create", "message.read"))) {
            String initial = this.initial(scopes);
            given().auth().oauth2(initial).contentType(ContentType.JSON)
                    .body(Map.of("grant_types", List.of("client_credentials")))
                    .post("/oauth-clients").then().statusCode(scopes.contains("client.create") ? 401 : 403);
            assertTrue(this.authorizations.findByToken(initial, OAuth2TokenType.ACCESS_TOKEN).getAccessToken().isActive());
        }
    }

    @Test
    void publishesOnlyOAuthRegistrationAndDoesNotExposeConfigurationReads() {
        given().get("/.well-known/oauth-authorization-server").then().statusCode(200)
                .body("registration_endpoint", equalTo("https://issuer.example/api/oauth-clients"));
        given().get("/.well-known/openid-configuration").then().statusCode(404);
        given().get("/oauth-clients").then().statusCode(404);
        given().contentType(ContentType.JSON).body("{}").post("/oauth2/register").then().statusCode(404);
        given().get("/other").then().statusCode(200).body(equalTo("unaffected"));
    }

    private String initial(Set<String> scopes) {
        return OAuthClientRegistrationTestSupport.initial(this.authorizations, this.clients, scopes);
    }
}
