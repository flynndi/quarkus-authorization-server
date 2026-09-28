package io.quarkiverse.authorization.server.it.authorizationcode;

import static io.quarkiverse.authorization.server.it.authorizationcode.authorizationserver.config.AuthorizationServerPersistence.CONFIDENTIAL_CLIENT_ID;
import static io.quarkiverse.authorization.server.it.authorizationcode.authorizationserver.config.AuthorizationServerPersistence.CONFIDENTIAL_CLIENT_REGISTRATION_ID;
import static io.quarkiverse.authorization.server.it.authorizationcode.authorizationserver.config.AuthorizationServerPersistence.CONFIDENTIAL_CLIENT_SECRET;
import static io.quarkiverse.authorization.server.it.authorizationcode.authorizationserver.config.AuthorizationServerPersistence.PUBLIC_CLIENT_ID;
import static io.quarkiverse.authorization.server.it.authorizationcode.authorizationserver.config.AuthorizationServerPersistence.PUBLIC_CLIENT_REGISTRATION_ID;
import static io.quarkiverse.authorization.server.it.authorizationcode.authorizationserver.config.AuthorizationServerPersistence.REDIRECT_URI;
import static io.quarkiverse.authorization.server.it.authorizationcode.authorizationserver.service.UserService.RESOURCE_OWNER;
import static io.quarkiverse.authorization.server.it.authorizationcode.authorizationserver.service.UserService.RESOURCE_OWNER_PASSWORD;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.sql.DataSource;

import jakarta.inject.Inject;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

@QuarkusTest
class AuthorizationCodeGrantTest {

    private static final String CODE_VERIFIER = "authorization-code-integration-test-verifier-0123456789";

    @Inject
    DataSource dataSource;

    @Inject
    RegisteredClientRepository registeredClientRepository;

    @Inject
    OAuth2AuthorizationService authorizationService;

    @Inject
    OAuth2AuthorizationConsentService authorizationConsentService;

    @Test
    void oauthRegistrationPersistsClientAndConsumesInitialTokenThroughJdbc() {
        String initial = java.util.UUID.randomUUID().toString();
        var bootstrap = this.registeredClientRepository.findByClientId(CONFIDENTIAL_CLIENT_ID);
        this.authorizationService.save(OAuth2Authorization.withRegisteredClient(bootstrap)
                .principalName(bootstrap.getClientId())
                .authorizationGrantType(
                        io.quarkiverse.authorization.server.model.AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(Set.of("client.create"))
                .accessToken(new io.quarkiverse.authorization.server.token.OAuth2AccessToken(
                        io.quarkiverse.authorization.server.token.OAuth2AccessToken.TokenType.BEARER, initial,
                        java.time.Instant.now(), java.time.Instant.now().plusSeconds(300), Set.of("client.create")))
                .build());
        var response = given().auth().oauth2(initial).contentType(ContentType.JSON)
                .body(Map.of("client_name", "JDBC registered", "grant_types", java.util.List.of("client_credentials"),
                        "token_endpoint_auth_method", "client_secret_post"))
                .post("/oauth2/register").then().statusCode(201).extract().response();
        String clientId = response.path("client_id"), secret = response.path("client_secret");
        var repository = new JdbcRegisteredClientRepository(this.dataSource);
        var stored = repository.findByClientId(clientId);
        assertEquals("JDBC registered", stored.getClientName());
        assertTrue(io.quarkus.elytron.security.common.BcryptUtil.matches(secret, stored.getClientSecret()));
        assertTrue(stored.getClientSettings().isRequireProofKey());
        assertFalse(new JdbcOAuth2AuthorizationService(this.dataSource, repository)
                .findByToken(initial, OAuth2TokenType.ACCESS_TOKEN).getAccessToken().isActive());
        String token = given().formParam("client_id", clientId).formParam("client_secret", secret)
                .formParam("grant_type", "client_credentials")
                .post("/oauth2/token").then().statusCode(200).extract().path("access_token");
        given().formParam("client_id", clientId).formParam("client_secret", secret).formParam("token", token)
                .post("/oauth2/introspect").then().statusCode(200).body("active", equalTo(true));
    }

    @BeforeEach
    void clearAuthorizations() throws SQLException {
        deleteByRegisteredClientId("oauth2_authorization_consent");
        deleteByRegisteredClientId("oauth2_authorization");
    }

    @Test
    void publicClientCompletesPkceConsentAndPersistsTheAuthorization() {
        assertJdbcServices();
        Map<String, String> cookies = login();
        Response consentPage = given()
                .cookies(cookies)
                .redirects().follow(false)
                .queryParam("response_type", "code")
                .queryParam("client_id", PUBLIC_CLIENT_ID)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "message.read")
                .queryParam("state", "client-state")
                .queryParam("code_challenge", codeChallenge(CODE_VERIFIER))
                .queryParam("code_challenge_method", "S256")
                .when().get("/oauth2/authorize")
                .then()
                .statusCode(200).contentType("text/html").header("Cache-Control", "no-store")
                .extract().response();

        String consentState = consentPage.htmlPath().getString("**.find { it.@name == 'state' }.@value");
        assertEquals(PUBLIC_CLIENT_ID, consentPage.htmlPath().getString("**.find { it.@name == 'client_id' }.@value"));

        String authorizationCode = authorizationCode(given()
                .cookies(cookies)
                .redirects().follow(false)
                .contentType(ContentType.URLENC)
                .formParam("client_id", PUBLIC_CLIENT_ID)
                .formParam("state", consentState)
                .formParam("scope", "message.read")
                .when().post("/oauth2/authorize")
                .then()
                .statusCode(302)
                .extract().response(), "client-state");

        String accessToken = given()
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "authorization_code")
                .formParam("client_id", PUBLIC_CLIENT_ID)
                .formParam("code", authorizationCode)
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("code_verifier", CODE_VERIFIER)
                .when().post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("token_type", equalTo("Bearer"))
                .body("scope", equalTo("message.read"))
                .extract().path("access_token");

        OAuth2Authorization authorization = this.authorizationService.findByToken(
                accessToken, OAuth2TokenType.ACCESS_TOKEN);
        assertNotNull(authorization);
        assertEquals(PUBLIC_CLIENT_REGISTRATION_ID, authorization.getRegisteredClientId());
        assertEquals(RESOURCE_OWNER, authorization.getPrincipalName());
        assertEquals(Set.of("message.read"), authorization.getAuthorizedScopes());
        assertTrue(authorization.getAuthorizationCode().isInvalidated());
        assertTrue(authorization.getAccessToken().isActive());

        OAuth2AuthorizationConsent consent = this.authorizationConsentService.findById(
                PUBLIC_CLIENT_REGISTRATION_ID, RESOURCE_OWNER);
        assertNotNull(consent);
        assertEquals(Set.of("message.read"), consent.getScopes());

        given()
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "authorization_code")
                .formParam("client_id", PUBLIC_CLIENT_ID)
                .formParam("code", authorizationCode)
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("code_verifier", CODE_VERIFIER)
                .when().post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_grant"));

        OAuth2Authorization replayedAuthorization = this.authorizationService.findByToken(
                accessToken, OAuth2TokenType.ACCESS_TOKEN);
        assertTrue(replayedAuthorization.getAccessToken().isInvalidated());
    }

    @Test
    void confidentialClientCompletesAuthorizationCodeExchange() {
        String authorizationCode = authorizationCode(given()
                .cookies(login())
                .redirects().follow(false)
                .queryParam("response_type", "code")
                .queryParam("client_id", CONFIDENTIAL_CLIENT_ID)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "message.read")
                .queryParam("state", "confidential-state")
                .queryParam("code_challenge", codeChallenge(CODE_VERIFIER))
                .queryParam("code_challenge_method", "S256")
                .when().get("/oauth2/authorize")
                .then()
                .statusCode(302)
                .extract().response(), "confidential-state");

        String accessToken = given()
                .auth().preemptive().basic(CONFIDENTIAL_CLIENT_ID, CONFIDENTIAL_CLIENT_SECRET)
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "authorization_code")
                .formParam("code", authorizationCode)
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("code_verifier", CODE_VERIFIER)
                .when().post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("token_type", equalTo("Bearer"))
                .extract().path("access_token");

        OAuth2Authorization authorization = this.authorizationService.findByToken(
                accessToken, OAuth2TokenType.ACCESS_TOKEN);
        assertNotNull(authorization);
        assertEquals(CONFIDENTIAL_CLIENT_REGISTRATION_ID, authorization.getRegisteredClientId());
        assertFalse(authorization.getAccessToken().isInvalidated());
        assertNull(this.authorizationConsentService.findById(
                CONFIDENTIAL_CLIENT_REGISTRATION_ID, RESOURCE_OWNER));
    }

    @Test
    void decliningNewConsentPreservesThePreviousGrant() {
        this.authorizationConsentService.save(OAuth2AuthorizationConsent.withId(PUBLIC_CLIENT_REGISTRATION_ID, RESOURCE_OWNER)
                .scope("message.read").build());
        Map<String, String> cookies = login();
        Response consentPage = given().cookies(cookies).redirects().follow(false)
                .queryParam("response_type", "code").queryParam("client_id", PUBLIC_CLIENT_ID)
                .queryParam("redirect_uri", REDIRECT_URI).queryParam("scope", "openid profile message.read")
                .queryParam("state", "declined-state").queryParam("code_challenge", codeChallenge(CODE_VERIFIER))
                .queryParam("code_challenge_method", "S256").get("/oauth2/authorize")
                .then().statusCode(200).contentType("text/html").extract().response();
        String state = consentPage.htmlPath().getString("**.find { it.@name == 'state' }.@value");
        assertEquals("checked", consentPage.htmlPath().getString("**.find { it.@disabled == 'disabled' }.@checked"));
        assertEquals("disabled", consentPage.htmlPath().getString("**.find { it.@disabled == 'disabled' }.@disabled"));
        Response denied = given().cookies(cookies).redirects().follow(false).contentType(ContentType.URLENC)
                .formParam("client_id", PUBLIC_CLIENT_ID).formParam("state", state).formParam("consent_action", "deny")
                .post("/oauth2/authorize").then().statusCode(302).extract().response();
        assertEquals("access_denied", queryParameters(denied.header("Location")).get("error"));
        assertEquals("declined-state", queryParameters(denied.header("Location")).get("state"));
        assertNull(this.authorizationService.findByToken(state, new OAuth2TokenType("state")));
        assertEquals(Set.of("message.read"), this.authorizationConsentService.findById(
                PUBLIC_CLIENT_REGISTRATION_ID, RESOURCE_OWNER).getScopes());
    }

    @Test
    void silentAuthorizationUsesPersistedConsentWithoutCreatingPendingRecords() throws SQLException {
        Map<String, Object> parameters = Map.of("response_type", "code", "client_id", PUBLIC_CLIENT_ID,
                "redirect_uri", REDIRECT_URI, "scope", "openid profile message.read", "state", "silent-jdbc",
                "code_challenge", AuthorizationCodeGrantTest.codeChallenge(CODE_VERIFIER), "code_challenge_method", "S256",
                "prompt", "none");
        Response anonymous = given().redirects().follow(false).queryParams(parameters).get("/oauth2/authorize")
                .then().statusCode(302).extract().response();
        assertEquals("login_required", AuthorizationCodeGrantTest.queryParameters(anonymous.header("Location")).get("error"));
        Map<String, String> cookies = AuthorizationCodeGrantTest.login();
        Response interactive = given().cookies(cookies).redirects().follow(false).queryParams(parameters)
                .get("/oauth2/authorize")
                .then().statusCode(302).extract().response();
        assertEquals("consent_required",
                AuthorizationCodeGrantTest.queryParameters(interactive.header("Location")).get("error"));
        try (Connection connection = this.dataSource.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement("SELECT COUNT(*) FROM oauth2_authorization WHERE registered_client_id=?")) {
            statement.setString(1, PUBLIC_CLIENT_REGISTRATION_ID);
            try (var rows = statement.executeQuery()) {
                assertTrue(rows.next());
                assertEquals(0, rows.getInt(1));
            }
        }
        this.authorizationConsentService.save(OAuth2AuthorizationConsent.withId(PUBLIC_CLIENT_REGISTRATION_ID, RESOURCE_OWNER)
                .scope("openid").scope("profile").scope("message.read").build());
        Response success = given().cookies(cookies).redirects().follow(false).queryParams(parameters).get("/oauth2/authorize")
                .then().statusCode(302).extract().response();
        String code = AuthorizationCodeGrantTest.authorizationCode(success, "silent-jdbc");
        var persisted = new JdbcOAuth2AuthorizationService(this.dataSource,
                new JdbcRegisteredClientRepository(this.dataSource)).findByToken(code, new OAuth2TokenType("code"));
        assertNotNull(persisted);
        assertEquals(RESOURCE_OWNER, persisted.getPrincipalName());
        assertEquals(Set.of("openid", "profile", "message.read"), persisted.getAuthorizedScopes());
    }

    @Test
    void pushedRequestSurvivesJdbcReadAndIsReplacedByConsentState() {
        var params = Map.of("response_type", "code", "client_id", PUBLIC_CLIENT_ID, "redirect_uri", REDIRECT_URI,
                "scope", "openid profile message.read", "state", "par-jdbc", "nonce", "jdbc-nonce",
                "code_challenge", AuthorizationCodeGrantTest.codeChallenge(CODE_VERIFIER), "code_challenge_method", "S256");
        String uri = given().formParams(params).post("/oauth2/par").then().statusCode(201).extract().path("request_uri");
        String id = uri.substring("urn:ietf:params:oauth:request_uri:".length());
        var reopened = new JdbcOAuth2AuthorizationService(this.dataSource, new JdbcRegisteredClientRepository(this.dataSource));
        var pending = reopened.findById(id);
        assertNotNull(pending);
        assertEquals(PUBLIC_CLIENT_REGISTRATION_ID, pending.getRegisteredClientId());
        assertNull(pending.getAttribute("state"));
        assertTrue(pending.getAttributes().values().stream().anyMatch(java.time.Instant.class::isInstance));
        io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest stored = pending.getAttribute(
                io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest.class.getName());
        assertEquals("par-jdbc", stored.getState());
        assertEquals("jdbc-nonce", stored.getAdditionalParameters().get("nonce"));
        var cookies = AuthorizationCodeGrantTest.login();
        var consent = given().redirects().follow(false).cookies(cookies).queryParam("client_id", PUBLIC_CLIENT_ID)
                .queryParam("request_uri", uri).get("/oauth2/authorize").then().statusCode(200).extract().response();
        String state = consent.htmlPath().getString("**.find { it.@name == 'state' }.@value");
        assertNull(reopened.findById(id));
        given().redirects().follow(false).cookies(cookies).queryParam("client_id", PUBLIC_CLIENT_ID)
                .queryParam("request_uri", uri).get("/oauth2/authorize").then().statusCode(400);
        given().redirects().follow(false).cookies(cookies).formParam("client_id", PUBLIC_CLIENT_ID).formParam("state", state)
                .formParam("consent_action", "deny").post("/oauth2/authorize").then().statusCode(302)
                .header("Location", org.hamcrest.Matchers.allOf(org.hamcrest.Matchers.containsString("error=access_denied"),
                        org.hamcrest.Matchers.containsString("state=par-jdbc")));
        assertNull(reopened.findByToken(state, new OAuth2TokenType("state")));
    }

    private void assertJdbcServices() {
        assertInstanceOf(JdbcRegisteredClientRepository.class, this.registeredClientRepository);
        assertInstanceOf(JdbcOAuth2AuthorizationService.class, this.authorizationService);
        assertInstanceOf(JdbcOAuth2AuthorizationConsentService.class, this.authorizationConsentService);
    }

    private static Map<String, String> login() {
        return given().redirects().follow(false).contentType(ContentType.URLENC)
                .formParam("j_username", RESOURCE_OWNER).formParam("j_password", RESOURCE_OWNER_PASSWORD)
                .post("/j_security_check").then().statusCode(302).extract().cookies();
    }

    private void deleteByRegisteredClientId(String table) throws SQLException {
        String sql = "DELETE FROM " + table + " WHERE registered_client_id IN (?, ?)";
        try (Connection connection = this.dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, PUBLIC_CLIENT_REGISTRATION_ID);
            statement.setString(2, CONFIDENTIAL_CLIENT_REGISTRATION_ID);
            statement.executeUpdate();
        }
    }

    private static String authorizationCode(Response response, String expectedState) {
        Map<String, String> parameters = queryParameters(response.getHeader("Location"));
        assertEquals(expectedState, parameters.get("state"));
        assertNotNull(parameters.get("code"));
        return parameters.get("code");
    }

    private static Map<String, String> queryParameters(String location) {
        assertNotNull(location);
        Map<String, String> parameters = new LinkedHashMap<>();
        String query = URI.create(location).getRawQuery();
        for (String parameter : query.split("&")) {
            String[] pair = parameter.split("=", 2);
            parameters.put(decode(pair[0]), pair.length == 2 ? decode(pair[1]) : "");
        }
        return parameters;
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String codeChallenge(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
