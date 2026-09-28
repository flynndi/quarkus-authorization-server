package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jose.jws.MacAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.runtime.client.authentication.JwtClientAssertionAuthenticationRequest;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

class PushedAuthorizationEndpointTest {
    private static final String PAR = "/requests/push";
    private static final String ISSUER = "https://issuer.example/server";
    private static final String REDIRECT = "https://client.example/callback?tenant=a";
    private static final String STATE = "par+state/with&symbols";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    @Inject
    RegisteredClientRepository clients;
    @Inject
    OAuth2AuthorizationService authorizations;

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> AuthorizationInteractionTestSupport.application(jar, false)
                    .addClasses(ClientAssertionTestSupport.class, RegistrationScopePolicy.class))
            .overrideConfigKey("quarkus.authorization-server.pushed-authorization-requests-enabled", "true")
            .overrideConfigKey("quarkus.authorization-server.oidc.client-registration.enabled", "true")
            .overrideConfigKey("quarkus.authorization-server.pushed-authorization-request-endpoint", PAR)
            .overrideConfigKey("quarkus.authorization-server.clients.wrong-grant.client-authentication-methods", "none");

    @ParameterizedTest
    @ValueSource(booleans = { false, true })
    void restoresLoginThenConsentOrCodeAndExchangesUsingThePushedPkce(boolean consent) {
        String client = consent ? "browser" : "direct";
        String uri = PushedAuthorizationEndpointTest.push(client, Map.of());
        var challenge = PushedAuthorizationEndpointTest.reference(uri, client, Map.of());
        challenge.then().statusCode(302).header("Location", endsWith("/server/auth/login"));
        String original = challenge.cookie("quarkus-redirect-location");
        var login = given().redirects().follow(false).cookies(challenge.cookies())
                .formParam("j_username", UUID.randomUUID().toString()).formParam("j_password", "password")
                .post("/j_security_check").then().statusCode(302).header("Location", equalTo(original)).extract().response();
        Response authorization = given().urlEncodingEnabled(false).redirects().follow(false).cookies(login.cookies())
                .get(original);
        if (consent) {
            authorization.then().statusCode(200).body(containsString("message.read"));
            String state = authorization.htmlPath().getString("**.find { it.@name == 'state' }.@value");
            assertNull(this.authorizations.findById(PushedAuthorizationEndpointTest.id(uri)));
            authorization = given().redirects().follow(false).cookies(login.cookies()).formParam("client_id", client)
                    .formParam("state", state).formParam("scope", "message.read").formParam("consent_action", "approve")
                    .post("/authorize");
        }
        authorization.then().statusCode(302);
        Map<String, String> query = PushedAuthorizationEndpointTest.query(authorization);
        assertEquals(STATE, query.get("state"));
        assertEquals("a", query.get("tenant"));
        assertNull(this.authorizations.findById(PushedAuthorizationEndpointTest.id(uri)));
        PushedAuthorizationEndpointTest.reference(uri, client, login.cookies()).then().statusCode(400).header("Location",
                nullValue());
        given().contentType(ContentType.URLENC).formParam("grant_type", "authorization_code").formParam("client_id", client)
                .formParam("code", query.get("code")).formParam("redirect_uri", REDIRECT).formParam("code_verifier", VERIFIER)
                .post("/oauth2/token").then().statusCode(200).body("access_token", notNullValue())
                .body("id_token", notNullValue());
    }

    @Test
    void silentErrorsPreserveTheReferenceAndNeverTreatTheParClientAsTheUser() {
        String uri = PushedAuthorizationEndpointTest.push("browser", Map.of("prompt", "none"));
        var anonymous = PushedAuthorizationEndpointTest.reference(uri, "browser", Map.of());
        assertEquals("login_required", PushedAuthorizationEndpointTest.query(anonymous).get("error"));
        assertNull(anonymous.cookie("quarkus-redirect-location"));
        var authenticated = PushedAuthorizationEndpointTest.reference(uri, "browser", PushedAuthorizationEndpointTest.login());
        assertEquals("consent_required", PushedAuthorizationEndpointTest.query(authenticated).get("error"));
        assertNotNull(this.authorizations.findById(PushedAuthorizationEndpointTest.id(uri)));
        String direct = PushedAuthorizationEndpointTest.push("direct", Map.of("prompt", "none"));
        var success = PushedAuthorizationEndpointTest.reference(direct, "direct", PushedAuthorizationEndpointTest.login());
        assertNotNull(PushedAuthorizationEndpointTest.query(success).get("code"));
    }

    @Test
    void onlyTheStoredRequestControlsRedirectScopesStateAndPrompt() {
        String uri = PushedAuthorizationEndpointTest.push("direct", Map.of());
        var result = given().redirects().follow(false).cookies(PushedAuthorizationEndpointTest.login())
                .queryParam("client_id", "direct").queryParam("request_uri", uri)
                .queryParam("redirect_uri", "https://attacker.example/").queryParam("scope", "unregistered")
                .queryParam("state", "attacker-state").queryParam("prompt", "none login").get("/authorize");
        result.then().statusCode(302).header("Location", startsWith(REDIRECT));
        assertEquals(STATE, PushedAuthorizationEndpointTest.query(result).get("state"));
        String other = PushedAuthorizationEndpointTest.push("direct", Map.of());
        PushedAuthorizationEndpointTest.reference(other, "browser", PushedAuthorizationEndpointTest.login())
                .then().statusCode(400).header("Location", nullValue());
        assertNotNull(this.authorizations.findById(PushedAuthorizationEndpointTest.id(other)));
        for (Object invalid : List.of("", "https://attacker.example/request", List.of(other, other))) {
            given().redirects().follow(false).queryParam("client_id", "direct").queryParam("request_uri", invalid)
                    .get("/authorize").then().statusCode(400).header("Location", nullValue());
        }
    }

    @Test
    void postReferenceIsAnInitialRequestAndCannotBypassConsentAuthentication() {
        String uri = PushedAuthorizationEndpointTest.push("browser", Map.of());
        given().redirects().follow(false).formParam("client_id", "browser").formParam("request_uri", uri)
                .post("/authorize").then().statusCode(303).header("Location", startsWith("/server/authorize?"));
        given().redirects().follow(false).cookies(PushedAuthorizationEndpointTest.login()).formParam("client_id", "browser")
                .formParam("request_uri", uri).post("/authorize").then().statusCode(200).body(containsString("message.read"));
        given().redirects().follow(false).formParam("client_id", "browser").formParam("state", uri)
                .formParam("scope", "message.read").post("/authorize").then().statusCode(302)
                .header("Location", endsWith("/server/auth/login"));
    }

    @Test
    void parErrorsAreJsonAndOrdinaryAuthorizationRemainsAvailable() {
        for (var invalid : Map.of("redirect_uri", "https://attacker.example/", "scope", "openid unregistered",
                "response_type", "token", "code_challenge_method", "plain", "prompt", "none login",
                "request_uri", "urn:example:other", "request", "unsupported.jwt").entrySet()) {
            var params = PushedAuthorizationEndpointTest.parameters("browser");
            params.put(invalid.getKey(), invalid.getValue());
            given().redirects().follow(false).formParams(params).post(PAR).then().statusCode(400)
                    .contentType(ContentType.JSON).header("Location", nullValue()).body("error", notNullValue());
        }
        for (String name : List.of("response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge",
                "prompt")) {
            var params = PushedAuthorizationEndpointTest.parameters("browser");
            params.put(name, List.of("", "other"));
            given().formParams(params).post(PAR).then().statusCode(400).body("error", equalTo("invalid_request"));
        }
        given().formParams(PushedAuthorizationEndpointTest.parameters("unknown")).post(PAR).then().statusCode(401);
        given().formParams(PushedAuthorizationEndpointTest.parameters("wrong-grant")).post(PAR).then().statusCode(400)
                .body("error", equalTo("unauthorized_client"));
        given().redirects().follow(false).queryParams(PushedAuthorizationEndpointTest.parameters("browser"))
                .get("/authorize").then().statusCode(302).header("Location", endsWith("/server/auth/login"));
        given().get(PAR).then().statusCode(405);
    }

    @Test
    void basicPostAndJwtUseClientSecurityAndNeverPersistCredentials() throws Exception {
        String secret = "0123456789abcdef".repeat(4);
        for (String method : List.of("client_secret_basic", "client_secret_post", "client_secret_jwt")) {
            String client = "par-" + method;
            this.clients.save(RegisteredClient.withId(client).clientId(client)
                    .clientSecret(method.equals("client_secret_jwt") ? secret : BcryptUtil.bcryptHash(secret))
                    .clientAuthenticationMethod(new ClientAuthenticationMethod(method))
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri(REDIRECT).scope("openid")
                    .scope("message.read")
                    .clientSettings(ClientSettings.builder().requireProofKey(true)
                            .tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256).build())
                    .build());
            var request = given().formParams(PushedAuthorizationEndpointTest.parameters(client));
            if (method.equals("client_secret_basic"))
                request.auth().preemptive().basic(client, secret);
            else if (method.equals("client_secret_post"))
                request.formParam("client_secret", secret);
            else
                request.formParam("client_assertion_type", JwtClientAssertionAuthenticationRequest.ASSERTION_TYPE)
                        .formParam("client_assertion",
                                ClientAssertionTestSupport.assertion(client, secret, ISSUER + PAR, null));
            String uri = request.post(PAR).then().statusCode(201).extract().path("request_uri");
            var saved = this.authorizations.findById(PushedAuthorizationEndpointTest.id(uri));
            io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest stored = saved.getAttribute(
                    io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest.class.getName());
            assertFalse(stored.getAdditionalParameters().containsKey("client_secret"));
            assertFalse(stored.getAdditionalParameters().containsKey("client_assertion"));
            assertFalse(stored.getAdditionalParameters().containsKey("client_assertion_type"));
        }
        given().auth().preemptive().basic("par-client_secret_basic", "wrong")
                .formParams(PushedAuthorizationEndpointTest.parameters("par-client_secret_basic")).post(PAR).then()
                .statusCode(401);
        given().auth().preemptive().basic("par-client_secret_basic", secret)
                .formParams(PushedAuthorizationEndpointTest.parameters("direct")).post(PAR).then().statusCode(400);
        given().auth().preemptive().basic("par-client_secret_basic", secret).contentType(ContentType.JSON).body("{}")
                .post(PAR).then().statusCode(415);
    }

    @Test
    void registeredClientsCanUseBothOrdinaryAndPushedRequests() {
        String initial = UUID.randomUUID().toString();
        var bootstrap = this.clients.findByClientId("direct");
        this.authorizations.save(
                io.quarkiverse.authorization.server.authorization.OAuth2Authorization.withRegisteredClient(bootstrap)
                        .principalName("direct").authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .authorizedScopes(java.util.Set.of("client.create"))
                        .accessToken(new io.quarkiverse.authorization.server.token.OAuth2AccessToken(
                                io.quarkiverse.authorization.server.token.OAuth2AccessToken.TokenType.BEARER,
                                initial, java.time.Instant.now(), java.time.Instant.now().plusSeconds(300),
                                java.util.Set.of("client.create")))
                        .build());
        var registration = given().auth().oauth2(initial).contentType(ContentType.JSON)
                .body(Map.of("redirect_uris", List.of(REDIRECT), "scope", "openid message.read",
                        "token_endpoint_auth_method", "none"))
                .post("/connect/register").then().statusCode(201)
                .extract().response();
        String client = registration.path("client_id");
        given().auth().oauth2(registration.path("registration_access_token")).queryParam("client_id", client)
                .get("/connect/register").then().statusCode(200).body("client_id", equalTo(client));
        given().redirects().follow(false).queryParams(PushedAuthorizationEndpointTest.parameters(client))
                .get("/authorize").then().statusCode(302).header("Location", endsWith("/server/auth/login"));
        assertNotNull(PushedAuthorizationEndpointTest.push(client, Map.of()));
    }

    @Test
    void currentClientPolicyIsRecheckedBeforeIssuance() {
        String uri = PushedAuthorizationEndpointTest.push("direct", Map.of());
        var client = this.clients.findByClientId("direct");
        try {
            this.clients.save(RegisteredClient.withId(client.getId()).clientId(client.getClientId())
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("https://client.example/new-callback").scope("openid").scope("message.read")
                    .clientSettings(client.getClientSettings()).build());
            PushedAuthorizationEndpointTest.reference(uri, "direct", PushedAuthorizationEndpointTest.login())
                    .then().statusCode(400).header("Location", nullValue());
            assertNotNull(this.authorizations.findById(PushedAuthorizationEndpointTest.id(uri)));
        } finally {
            this.clients.save(client);
        }
    }

    @Test
    void publishesOnlyTheEnabledCustomEndpoint() {
        for (String discovery : List.of("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration")) {
            given().get(discovery).then().statusCode(200).body("pushed_authorization_request_endpoint", equalTo(ISSUER + PAR))
                    .body("$", not(hasKey("require_pushed_authorization_requests")));
        }
        given().formParams(PushedAuthorizationEndpointTest.parameters("direct")).post("/oauth2/par").then().statusCode(404);
    }

    private static Map<String, Object> parameters(String client) {
        return new LinkedHashMap<>(Map.of("client_id", client, "response_type", "code", "redirect_uri", REDIRECT,
                "scope", "openid message.read", "state", STATE, "code_challenge", CHALLENGE, "code_challenge_method", "S256"));
    }

    private static String push(String client, Map<String, Object> extra) {
        var params = PushedAuthorizationEndpointTest.parameters(client);
        params.putAll(extra);
        return given().formParams(params).post(PAR).then().statusCode(201).header("Cache-Control", containsString("no-store"))
                .body("expires_in", equalTo(300)).extract().path("request_uri");
    }

    private static Response reference(String uri, String client, Map<String, String> cookies) {
        return given().redirects().follow(false).cookies(cookies).queryParam("client_id", client)
                .queryParam("request_uri", uri).get("/authorize");
    }

    private static Map<String, String> login() {
        return given().redirects().follow(false).formParam("j_username", UUID.randomUUID().toString())
                .formParam("j_password", "password")
                .post("/j_security_check").then().statusCode(302).extract().cookies();
    }

    private static String id(String uri) {
        return uri.substring("urn:ietf:params:oauth:request_uri:".length());
    }

    private static Map<String, String> query(Response response) {
        response.then().statusCode(302);
        Map<String, String> result = new LinkedHashMap<>();
        for (String parameter : URI.create(response.header("Location")).getRawQuery().split("&")) {
            String[] pair = parameter.split("=", 2);
            result.put(pair[0], URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
        }
        return result;
    }
}
