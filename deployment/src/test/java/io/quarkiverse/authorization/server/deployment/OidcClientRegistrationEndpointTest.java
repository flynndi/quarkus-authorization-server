package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.sun.net.httpserver.HttpServer;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.runtime.client.BcryptClientSecretVerifier;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.http.Header;
import io.restassured.http.Headers;
import io.restassured.response.Response;

class OidcClientRegistrationEndpointTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(ClientRegistrationTestApplication::application);
    private static final String REGISTRATION = """
            {"redirect_uris":["https://rp.example/callback"],"client_name":"Dynamic RP",
             "grant_types":["authorization_code","password","refresh_token"], "scope":"openid"}
            """;
    @Inject
    OAuth2AuthorizationService service;
    @Inject
    RegisteredClientRepository clients;

    @Test
    void registersReadsAndAuthenticatesTheNewConfidentialClient() {
        given().get("/.well-known/openid-configuration").then().statusCode(200)
                .body("registration_endpoint", equalTo("https://issuer.example/api/clients"));
        String initial = initial(Set.of("client.create"));
        Response response = register(initial, REGISTRATION).then().statusCode(201).contentType(ContentType.JSON)
                .header("Cache-Control", equalTo("no-store")).header("Pragma", equalTo("no-cache"))
                .body("client_id", notNullValue()).body("client_secret", notNullValue())
                .body("client_secret_expires_at", equalTo(0)).body("scope", equalTo("openid"))
                .body("id_token_signed_response_alg", equalTo("RS256")).extract().response();
        String clientId = response.path("client_id");
        String secret = response.path("client_secret");
        String accessToken = response.path("registration_access_token");
        assertEquals("https://issuer.example/api/clients?client_id=" + clientId, response.path("registration_client_uri"));
        var client = this.clients.findByClientId(clientId);
        assertNotEquals(secret, client.getClientSecret());
        assertTrue(new BcryptClientSecretVerifier().matches(secret, client.getClientSecret()));
        assertFalse(this.service.findByToken(initial, OAuth2TokenType.ACCESS_TOKEN).getAccessToken().isActive());
        assertFalse(this.service.findByToken(initial, OAuth2TokenType.ACCESS_TOKEN).getRefreshToken().isActive());
        var registrationAuthorization = this.service.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN);
        assertEquals(Set.of("client.read"), registrationAuthorization.getAccessToken().getToken().getScopes());
        assertEquals(client.getId(), registrationAuthorization.getRegisteredClientId());
        assertEquals(3, accessToken.split("\\.").length);
        given().auth().oauth2(accessToken).queryParam("client_id", clientId).get("/clients").then().statusCode(200)
                .body("client_id", equalTo(clientId)).body("client_name", equalTo("Dynamic RP"))
                .body("registration_client_uri", equalTo(response.path("registration_client_uri")))
                .body("$", not(hasKey("client_secret"))).body("$", not(hasKey("client_secret_expires_at")))
                .body("$", not(hasKey("registration_access_token")));
        register(initial, REGISTRATION).then().statusCode(401).body("error", equalTo("invalid_token"));
        Response tokens = given().auth().preemptive().basic(clientId, secret).contentType(ContentType.URLENC)
                .formParam("grant_type", "password").formParam("username", "owner").formParam("password", "password")
                .post("/oauth2/token").then().statusCode(200).body("id_token", notNullValue()).extract().response();
        given().auth().oauth2(tokens.<String> path("access_token")).get("/userinfo").then().statusCode(200).body("sub",
                equalTo("owner"));
        // Registration-token issuance must not grant Client Credentials permission to this client.
        given().auth().preemptive().basic(clientId, secret).contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials").post("/oauth2/token").then().statusCode(400)
                .body("error", equalTo("unauthorized_client"));
    }

    @ParameterizedTest
    @ValueSource(strings = { "client_secret_basic", "client_secret_post" })
    void dynamicallyRegisteredClientCanUseClientCredentialsAndReadItsGrantMetadata(String method) {
        Response registration = register(initial(Set.of("client.create")), """
                {"redirect_uris":["https://rp.example/callback"],"grant_types":["client_credentials"],
                 "token_endpoint_auth_method":"%s","scope":"message.read"}
                """.formatted(method)).then().statusCode(201).body("client_secret", notNullValue())
                .body("token_endpoint_auth_method", equalTo(method))
                // The registration converter defaults missing response_types to code.
                .body("grant_types", containsInAnyOrder("client_credentials", "authorization_code"))
                .body("response_types", contains("code")).extract().response();
        String clientId = registration.path("client_id");
        String secret = registration.path("client_secret");
        assertTrue(new BcryptClientSecretVerifier().matches(secret, this.clients.findByClientId(clientId).getClientSecret()));

        var tokenRequest = given().contentType(ContentType.URLENC);
        if ("client_secret_post".equals(method)) {
            tokenRequest.formParam("client_id", clientId).formParam("client_secret", secret);
        } else {
            tokenRequest.auth().preemptive().basic(clientId, secret);
        }
        String token = tokenRequest
                .formParam("grant_type", "client_credentials").formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200).body("scope", equalTo("message.read"))
                .body("$", not(hasKey("refresh_token"))).body("$", not(hasKey("id_token")))
                .extract().path("access_token");
        var authorization = this.service.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        assertEquals(clientId, authorization.getPrincipalName());
        assertEquals(AuthorizationGrantType.CLIENT_CREDENTIALS, authorization.getAuthorizationGrantType());
        assertEquals(Set.of("message.read"), authorization.getAuthorizedScopes());
        assertTrue(authorization.getAttributes().isEmpty());

        given().auth().oauth2(registration.<String> path("registration_access_token")).queryParam("client_id", clientId)
                .get("/clients").then().statusCode(200)
                .body("token_endpoint_auth_method", equalTo(method))
                .body("grant_types", containsInAnyOrder("client_credentials", "authorization_code"))
                .body("$", not(hasKey("client_secret")));
    }

    @Test
    void dynamicallyRegisteredPublicDeviceClientCanStartDeviceAuthorization() {
        Response registration = register(initial(Set.of("client.create")), """
                {"redirect_uris":["https://rp.example/callback"],
                 "grant_types":["urn:ietf:params:oauth:grant-type:device_code"],
                 "token_endpoint_auth_method":"none","scope":"message.read"}
                """).then().statusCode(201).body("$", not(hasKey("client_secret")))
                .body("grant_types", containsInAnyOrder("authorization_code",
                        AuthorizationGrantType.DEVICE_CODE.getValue()))
                .extract().response();

        given().contentType(ContentType.URLENC)
                .formParam("client_id", registration.<String> path("client_id"))
                .formParam("scope", "message.read")
                .post("/oauth2/device_authorization").then().statusCode(200)
                .body("device_code", notNullValue()).body("user_code", notNullValue());
    }

    @ParameterizedTest
    @ValueSource(strings = { "private_key_jwt", "client_secret_jwt" })
    void registersJwtClientAndUsesReturnedMetadataForActualAuthentication(String method) throws Exception {
        String jwks = "private_key_jwt".equals(method)
                ? ",\"jwks_uri\":\"https://localhost:8444/api/oauth2/jwks\""
                : "";
        // This fixture explicitly permits its local HTTPS origin and trusts only the test CA.
        var registration = register(initial(Set.of("client.create")), """
                {"redirect_uris":["https://rp.example/callback"],"grant_types":["client_credentials"],
                 "scope":"message.read","token_endpoint_auth_method":"%s"%s}
                """.formatted(method, jwks)).then().statusCode(201)
                .body("token_endpoint_auth_method", equalTo(method)).extract().response();
        String clientId = registration.path("client_id");
        String secret = registration.path("client_secret");
        var client = this.clients.findByClientId(clientId);
        if ("private_key_jwt".equals(method)) {
            assertEquals(null, secret);
            assertEquals(null, client.getClientSecret());
            assertEquals("RS256", registration.path("token_endpoint_auth_signing_alg"));
        } else {
            assertTrue(secret != null && secret.length() >= 64);
            assertEquals(secret, client.getClientSecret(), "HMAC verification requires the original key, not bcrypt");
            assertEquals("HS256", registration.path("token_endpoint_auth_signing_alg"));
        }
        String assertion = ClientAssertionTestSupport.assertion(clientId, secret,
                "https://issuer.example/api", "registration-test-key");
        given().contentType(ContentType.URLENC).formParam("client_id", clientId)
                .formParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .formParam("client_assertion", assertion).formParam("grant_type", "client_credentials")
                .formParam("scope", "message.read").post("/oauth2/token").then().statusCode(200)
                .body("access_token", notNullValue());
        given().auth().oauth2(registration.<String> path("registration_access_token")).queryParam("client_id", clientId)
                .get("/clients").then().statusCode(200)
                .body("token_endpoint_auth_method", equalTo(method))
                .body("token_endpoint_auth_signing_alg", equalTo(registration.path("token_endpoint_auth_signing_alg")))
                .body("$", not(hasKey("client_secret")));
    }

    @Test
    void customRegistrationValidatorCannotAllowHttpOrUnapprovedPrivateJwks() {
        for (String method : List.of("private_key_jwt", "self_signed_tls_client_auth")) {
            for (String url : List.of("http://127.0.0.1:12345/keys", "http://client.example/keys",
                    "https://127.0.0.1:12345/keys", "https://localhost:12345/keys", "https://[::1]/keys",
                    "https://169.254.169.254/keys", "https://10.0.0.1/keys", "https://[fd00::1]/keys")) {
                register(initial(Set.of("client.create")), """
                        {"redirect_uris":["https://rp.example/callback"],"token_endpoint_auth_method":"%s",
                         "jwks_uri":"%s"}
                        """.formatted(method, url)).then().statusCode(400)
                        .body("error", equalTo("invalid_client_metadata"))
                        .body("error_description", containsString("jwks_uri"));
            }
        }
    }

    @Test
    void repositorySuppliedHttpJwksNeverReceivesTheInvalidAssertionRequest() throws Exception {
        var requests = new AtomicInteger();
        var target = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        target.createContext("/jwks", exchange -> {
            requests.incrementAndGet();
            byte[] body = "{\"keys\":[]}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (var output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        target.start();
        try {
            String id = UUID.randomUUID().toString();
            this.clients.save(RegisteredClient.withId(id).clientId(id)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .clientSettings(ClientSettings.builder()
                            .jwkSetUrl("http://127.0.0.1:" + target.getAddress().getPort() + "/jwks")
                            .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
                            .build())
                    .build());
            given().contentType(ContentType.URLENC).formParam("client_id", id)
                    .formParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                    .formParam("client_assertion",
                            ClientAssertionTestSupport.assertion(id, null, "https://issuer.example/api", "wrong-key"))
                    .formParam("grant_type", "client_credentials").post("/oauth2/token").then().statusCode(401)
                    .body("error", equalTo("invalid_client"));
            assertEquals(0, requests.get());
        } finally {
            target.stop(0);
        }
    }

    @Test
    void implementedGrantsDoNotRelaxOidcRegistrationShapeOrEnableUnknownGrants() {
        String initial = initial(Set.of("client.create"));
        for (String json : List.of("{\"grant_types\":[\"client_credentials\"]}",
                "{\"redirect_uris\":[],\"grant_types\":[\"client_credentials\"]}",
                "{\"redirect_uris\":[\"https://rp.example/callback\"],\"grant_types\":[\"client_credentials\"],\"response_types\":[]}")) {
            register(initial, json).then().statusCode(400).body("error", equalTo("invalid_request"));
        }
        for (String grant : List.of("urn:example:unsupported-grant")) {
            register(initial, """
                    {"redirect_uris":["https://rp.example/callback"],"grant_types":["client_credentials","%s"]}
                    """.formatted(grant)).then().statusCode(400).body("error", equalTo("invalid_client_metadata"));
        }
        assertTrue(this.service.findByToken(initial, OAuth2TokenType.ACCESS_TOKEN).getAccessToken().isActive());
    }

    @Test
    void dynamicallyRegistersTokenExchangeClient() {
        Response registration = register(initial(Set.of("client.create")), """
                {"redirect_uris":["https://rp.example/callback"],
                 "grant_types":["urn:ietf:params:oauth:grant-type:token-exchange"],
                 "token_endpoint_auth_method":"client_secret_basic","scope":"message.read"}
                """).then().statusCode(201).body("client_secret", notNullValue())
                .body("grant_types", containsInAnyOrder("authorization_code",
                        AuthorizationGrantType.TOKEN_EXCHANGE.getValue()))
                .extract().response();

        assertTrue(this.clients.findByClientId(registration.<String> path("client_id"))
                .getAuthorizationGrantTypes().contains(AuthorizationGrantType.TOKEN_EXCHANGE));
    }

    @Test
    void registersPublicClientAndCompletesOidcCodePkce() throws Exception {
        Response response = register(initial(Set.of("client.create")), """
                {"redirect_uris":["https://rp.example/callback"], "token_endpoint_auth_method":"none", "scope":"openid"}
                """).then().statusCode(201).body("$", not(hasKey("client_secret"))).extract().response();
        String clientId = response.path("client_id");
        String verifier = "a".repeat(43);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        String location = given().redirects().follow(false).auth().preemptive().basic("owner", "password")
                .queryParam("response_type", "code").queryParam("client_id", clientId).queryParam("scope", "openid")
                .queryParam("redirect_uri", "https://rp.example/callback").queryParam("nonce", "registration-nonce")
                .queryParam("code_challenge", challenge).queryParam("code_challenge_method", "S256")
                .get("/oauth2/authorize").then().statusCode(302).extract().header("Location");
        String code = null;
        for (String parameter : URI.create(location).getRawQuery().split("&")) {
            if (parameter.startsWith("code="))
                code = URLDecoder.decode(parameter.substring(5), StandardCharsets.UTF_8);
        }
        assertTrue(code != null, location);
        Response tokens = given().contentType(ContentType.URLENC).formParam("grant_type", "authorization_code")
                .formParam("client_id", clientId).formParam("code", code).formParam("code_verifier", verifier)
                .formParam("redirect_uri", "https://rp.example/callback").post("/oauth2/token").then().statusCode(200)
                .body("id_token", notNullValue()).body("$", not(hasKey("refresh_token"))).extract().response();
        given().auth().oauth2(tokens.<String> path("access_token")).get("/userinfo").then().statusCode(200);
        given().auth().oauth2(response.<String> path("registration_access_token")).queryParam("client_id", clientId)
                .get("/clients").then().statusCode(200).body("token_endpoint_auth_method", equalTo("none"));
    }

    @Test
    void isolatesControlScopesAndClientBinding() {
        String initial = initial(Set.of("client.create"));
        given().auth().oauth2(initial).queryParam("client_id", "bootstrap").get("/clients").then().statusCode(403)
                .body("error", equalTo("insufficient_scope"));
        register(initial(Set.of("client.create", "openid")), REGISTRATION).then().statusCode(401).body("error",
                equalTo("invalid_token"));
        register(initial(Set.of("openid")), REGISTRATION).then().statusCode(403).body("error", equalTo("insufficient_scope"));
        var response = register(initial, REGISTRATION).then().statusCode(201).extract().response();
        String token = response.path("registration_access_token");
        register(token, REGISTRATION).then().statusCode(403).body("error", equalTo("insufficient_scope"));
        for (String other : List.of("bootstrap", "unknown")) {
            given().auth().oauth2(token).queryParam("client_id", other).get("/clients").then().statusCode(401)
                    .body("error", equalTo("invalid_client"));
        }
        var authorization = this.service.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        this.service.save(OAuth2Authorization.from(authorization).token(authorization.getAccessToken().getToken(),
                metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true)).build());
        given().auth().oauth2(token).queryParam("client_id", response.<String> path("client_id")).get("/clients").then()
                .statusCode(401);
    }

    @Test
    void rejectsUnauthenticatedMalformedAndDuplicateRequestsWithoutConsumingTheInitialToken() {
        given().contentType(ContentType.JSON).body(REGISTRATION).post("/clients").then().statusCode(401)
                .header("WWW-Authenticate", equalTo("Bearer"));
        String initial = initial(Set.of("client.create"));
        given().auth().oauth2(initial).contentType(ContentType.URLENC).body("client_name=wrong-type")
                .post("/clients").then().statusCode(415);
        for (String body : List.of("{broken", "null", "{}",
                "{\"redirect_uris\":[\"https://rp.example\"],\"scope\":\"openid\",\"scope\":\"profile\"}")) {
            register(initial, body).then().statusCode(400).body("error", equalTo("invalid_request"));
        }
        register(initial, "{\"redirect_uris\":[\"https://rp.example#fragment\"]}")
                .then().statusCode(400).body("error", equalTo("invalid_redirect_uri"));
        register(initial, "{\"redirect_uris\":[\"https://rp.example\"],\"token_endpoint_auth_method\":\"private_key_jwt\"}")
                .then().statusCode(400).body("error", equalTo("invalid_client_metadata"));
        assertTrue(this.service.findByToken(initial, OAuth2TokenType.ACCESS_TOKEN).getAccessToken().isActive());
        String token = register(initial, REGISTRATION).then().statusCode(201).extract().path("registration_access_token");
        given().auth().oauth2(token).get("/clients").then().statusCode(400).body("error", equalTo("invalid_request"));
        given().auth().oauth2(token).queryParam("client_id", "a", "b").get("/clients").then().statusCode(400);
        given().headers(
                new Headers(new Header("Authorization", "Bearer " + token), new Header("Authorization", "Bearer other")))
                .get("/clients").then().statusCode(400).body("error", equalTo("invalid_request"));
        given().auth().oauth2(token).put("/clients").then().statusCode(404);
        given().get("/connect/register").then().statusCode(404);
        given().header("Authorization", "Bearer invalid").get("/other").then().statusCode(200).body(equalTo("unaffected"));
        given().auth().preemptive().basic("owner", "password").get("/clients").then().statusCode(401)
                .header("WWW-Authenticate", containsString("Bearer"));
    }

    private String initial(Set<String> scopes) {
        String token = UUID.randomUUID().toString();
        this.service.save(OAuth2Authorization.withRegisteredClient(this.clients.findByClientId("bootstrap"))
                .principalName("bootstrap").authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(scopes).accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token,
                        Instant.now(), Instant.now().plusSeconds(300), scopes))
                .refreshToken(new OAuth2RefreshToken(token + "-refresh", Instant.now(), Instant.now().plusSeconds(600)))
                .build());
        return token;
    }

    private static Response register(String token, String json) {
        return given().auth().oauth2(token).contentType(ContentType.JSON).body(json).post("/clients");
    }
}
