package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

/** Exercises the same protocol boundaries with Quarkus proactive authentication enabled and disabled. */
abstract class AbstractAuthorizationInteractionTest {
    private static final String REDIRECT = "https://client.example/callback?tenant=a";
    private static final String STATE = "client+state/with&symbols";
    @Inject
    OAuth2AuthorizationService authorizations;
    @Inject
    OAuth2AuthorizationConsentService consents;
    @Inject
    RegisteredClientRepository clients;

    @ParameterizedTest
    @ValueSource(booleans = { false, true })
    void anonymousSilentRequestReturnsLoginRequiredWithoutAChallenge(boolean post) {
        var response = AbstractAuthorizationInteractionTest.authorize(post, Map.of(),
                AbstractAuthorizationInteractionTest.parameters());
        AbstractAuthorizationInteractionTest.assertError(response, "login_required");
        assertFalse(response.cookies().containsKey("quarkus-redirect-location"));
    }

    @ParameterizedTest
    @ValueSource(booleans = { false, true })
    void signedInSilentRequestReturnsConsentRequiredWithoutShowingConsent(boolean post) {
        var response = AbstractAuthorizationInteractionTest.authorize(post,
                AbstractAuthorizationInteractionTest.login(UUID.randomUUID().toString()),
                AbstractAuthorizationInteractionTest.parameters());
        AbstractAuthorizationInteractionTest.assertError(response, "consent_required");
        assertFalse(response.cookies().containsKey("quarkus-redirect-location"));
    }

    @ParameterizedTest
    @ValueSource(booleans = { false, true })
    void silentRequestIssuesCodeWhenConsentIsDisabled(boolean post) {
        var parameters = AbstractAuthorizationInteractionTest.parameters();
        parameters.put("client_id", "direct");
        String user = UUID.randomUUID().toString();
        var response = AbstractAuthorizationInteractionTest.authorize(post, AbstractAuthorizationInteractionTest.login(user),
                parameters);
        response.then().statusCode(302);
        var query = AbstractAuthorizationInteractionTest.query(response.header("Location"));
        assertEquals(STATE, query.get("state"));
        var saved = this.authorizations.findByToken(query.get("code"), new OAuth2TokenType("code"));
        assertNotNull(saved);
        assertEquals(user, saved.getPrincipalName());
    }

    @Test
    void previousConsentAllowsSilentAuthorization() {
        String user = UUID.randomUUID().toString();
        this.consents.save(OAuth2AuthorizationConsent.withId(this.clients.findByClientId("browser").getId(), user)
                .scope("openid").scope("message.read").build());
        var response = AbstractAuthorizationInteractionTest.authorize(false, AbstractAuthorizationInteractionTest.login(user),
                AbstractAuthorizationInteractionTest.parameters());
        response.then().statusCode(302).header("Location", containsString("&code="));
        assertEquals(STATE, AbstractAuthorizationInteractionTest.query(response.header("Location")).get("state"));
    }

    @Test
    void rejectsInvalidRequestsBeforeLoginAndNeverRedirectsToUntrustedUris() {
        for (boolean post : new boolean[] { false, true }) {
            for (var invalid : Map.of("client_id", "unknown", "redirect_uri", "https://attacker.example/callback",
                    "response_type", "token").entrySet()) {
                var parameters = AbstractAuthorizationInteractionTest.parameters();
                parameters.remove("prompt");
                parameters.put(invalid.getKey(), invalid.getValue());
                var response = AbstractAuthorizationInteractionTest.authorize(post, Map.of(), parameters);
                response.then().statusCode(400).header("Location", nullValue());
                assertFalse(response.cookies().containsKey("quarkus-redirect-location"));
            }
            for (var invalid : Map.of("scope", "openid unregistered", "code_challenge_method", "plain",
                    "client_id", "wrong-grant").entrySet()) {
                var parameters = AbstractAuthorizationInteractionTest.parameters();
                parameters.remove("prompt");
                parameters.put(invalid.getKey(), invalid.getValue());
                var response = AbstractAuthorizationInteractionTest.authorize(post, Map.of(), parameters);
                String expected = invalid.getKey().equals("scope") ? "invalid_scope"
                        : invalid.getKey().equals("client_id") ? "unauthorized_client" : "invalid_request";
                AbstractAuthorizationInteractionTest.assertError(response, expected);
                assertFalse(response.cookies().containsKey("quarkus-redirect-location"));
            }
            var missingPkce = AbstractAuthorizationInteractionTest.parameters();
            missingPkce.remove("code_challenge");
            AbstractAuthorizationInteractionTest.assertError(
                    AbstractAuthorizationInteractionTest.authorize(post, Map.of(), missingPkce), "invalid_request");
        }
    }

    @Test
    void rejectsMalformedPromptAndMixedNoneValues() {
        for (boolean post : new boolean[] { false, true }) {
            for (Object prompt : List.of("", " ", "none login", "consent none", "none select_account", "none unknown",
                    "none\tlogin", List.of("none", "none"))) {
                var parameters = AbstractAuthorizationInteractionTest.parameters();
                parameters.put("prompt", prompt);
                var response = AbstractAuthorizationInteractionTest.authorize(post, Map.of(), parameters);
                if (prompt instanceof List<?>)
                    response.then().statusCode(400).header("Location", nullValue());
                else
                    AbstractAuthorizationInteractionTest.assertError(response, "invalid_request");
                assertFalse(response.cookies().containsKey("quarkus-redirect-location"));
            }
        }
    }

    @Test
    void duplicateOptionalParametersCannotSkipValidationWithABlankFirstValue() {
        for (String name : List.of("redirect_uri", "scope", "state", "code_challenge", "code_challenge_method")) {
            var parameters = AbstractAuthorizationInteractionTest.parameters();
            parameters.put(name, List.of("", parameters.get(name)));
            AbstractAuthorizationInteractionTest.authorize(false, Map.of(), parameters).then().statusCode(400)
                    .body("error", equalTo("invalid_request")).header("Location", nullValue());
        }
    }

    @Test
    void formLoginRestoresAValidatedGetAndCanApproveOrDenyConsent() {
        for (String action : List.of("approve", "deny")) {
            var parameters = AbstractAuthorizationInteractionTest.parameters();
            parameters.remove("prompt");
            var challenge = AbstractAuthorizationInteractionTest.authorize(false, Map.of(), parameters);
            challenge.then().statusCode(302).header("Location", endsWith("/server/auth/login"));
            String original = challenge.cookie("quarkus-redirect-location");
            assertNotNull(original);
            var login = given().redirects().follow(false).cookies(challenge.cookies())
                    .formParam("j_username", UUID.randomUUID().toString())
                    .formParam("j_password", "password").post("/j_security_check");
            login.then().statusCode(302).header("Location", equalTo(original));
            var consent = given().urlEncodingEnabled(false).cookies(login.cookies()).get(original).then().statusCode(200)
                    .extract().response();
            String pendingState = consent.htmlPath().getString("**.find { it.@name == 'state' }.@value");
            var result = given().redirects().follow(false).cookies(login.cookies()).contentType(ContentType.URLENC)
                    .formParam("client_id", "browser").formParam("state", pendingState).formParam("scope", "message.read")
                    .formParam("consent_action", action).post("/authorize");
            if (action.equals("approve"))
                result.then().statusCode(302).header("Location", containsString("&code="));
            else
                AbstractAuthorizationInteractionTest.assertError(result, "access_denied");
            assertEquals(STATE, AbstractAuthorizationInteractionTest.query(result.header("Location")).get("state"));
        }
    }

    @Test
    void validPostIsNormalizedBeforeFormLoginSoParametersAreNotLost() {
        var parameters = AbstractAuthorizationInteractionTest.parameters();
        parameters.remove("prompt");
        parameters.put("client_id", "direct");
        var normalized = AbstractAuthorizationInteractionTest.authorize(true, Map.of(), parameters);
        normalized.then().statusCode(303).header("Location", org.hamcrest.Matchers.startsWith("/server/authorize?"));
        assertFalse(normalized.cookies().containsKey("quarkus-redirect-location"));
        String getRequest = normalized.header("Location");
        var challenge = given().basePath("").urlEncodingEnabled(false).redirects().follow(false).get(getRequest);
        challenge.then().statusCode(302).header("Location", endsWith("/server/auth/login"));
        String original = challenge.cookie("quarkus-redirect-location");
        var login = given().redirects().follow(false).cookies(challenge.cookies())
                .formParam("j_username", UUID.randomUUID().toString())
                .formParam("j_password", "password").post("/j_security_check");
        login.then().statusCode(302).header("Location", equalTo(original));
        var completed = given().urlEncodingEnabled(false).cookies(login.cookies()).redirects().follow(false).get(original);
        completed.then().statusCode(302).header("Location", containsString("&code="));
        assertEquals(STATE, AbstractAuthorizationInteractionTest.query(completed.header("Location")).get("state"));
    }

    @Test
    void anonymousConsentCannotConsumeThePendingRequest() {
        var parameters = AbstractAuthorizationInteractionTest.parameters();
        parameters.remove("prompt");
        Map<String, String> cookies = AbstractAuthorizationInteractionTest.login(UUID.randomUUID().toString());
        var consent = AbstractAuthorizationInteractionTest.authorize(false, cookies, parameters);
        consent.then().statusCode(200);
        String state = consent.htmlPath().getString("**.find { it.@name == 'state' }.@value");
        given().redirects().follow(false).formParam("client_id", "browser").formParam("state", state)
                .formParam("scope", "message.read").formParam("consent_action", "approve").post("/authorize")
                .then().statusCode(302).header("Location", endsWith("/server/auth/login"));
        assertNotNull(this.authorizations.findByToken(state, new OAuth2TokenType("state")));
        given().redirects().follow(false).cookies(cookies).formParam("client_id", "browser").formParam("state", state)
                .formParam("scope", "message.read").formParam("consent_action", "approve").post("/authorize")
                .then().statusCode(302).header("Location", containsString("&code="));
    }

    @Test
    void promptNoneDoesNotChangePlainOAuthRequests() {
        var parameters = AbstractAuthorizationInteractionTest.parameters();
        parameters.put("scope", "message.read");
        AbstractAuthorizationInteractionTest.authorize(false, Map.of(), parameters).then().statusCode(302)
                .header("Location", endsWith("/server/auth/login"));
    }

    private static Map<String, Object> parameters() {
        return new LinkedHashMap<>(Map.of("client_id", "browser", "response_type", "code", "redirect_uri", REDIRECT,
                "scope", "openid message.read", "state", STATE, "code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method", "S256", "prompt", "none"));
    }

    private static Response authorize(boolean post, Map<String, String> cookies, Map<String, Object> parameters) {
        var request = given().redirects().follow(false).cookies(cookies).urlEncodingEnabled(true);
        return post ? request.contentType(ContentType.URLENC).formParams(parameters).post("/authorize")
                : request.queryParams(parameters).get("/authorize");
    }

    private static Map<String, String> login(String user) {
        return given().redirects().follow(false).formParam("j_username", user).formParam("j_password", "password")
                .post("/j_security_check").then().statusCode(302).extract().cookies();
    }

    private static void assertError(Response response, String code) {
        response.then().statusCode(302);
        URI location = URI.create(response.header("Location"));
        assertEquals("client.example", location.getHost());
        var query = AbstractAuthorizationInteractionTest.query(location.toString());
        assertEquals("a", query.get("tenant"));
        assertEquals(code, query.get("error"));
        assertEquals(STATE, query.get("state"));
    }

    private static Map<String, String> query(String location) {
        Map<String, String> result = new LinkedHashMap<>();
        for (String pair : URI.create(location).getRawQuery().split("&")) {
            String[] parts = pair.split("=", 2);
            result.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
                    URLDecoder.decode(parts[1], StandardCharsets.UTF_8));
        }
        return result;
    }
}
