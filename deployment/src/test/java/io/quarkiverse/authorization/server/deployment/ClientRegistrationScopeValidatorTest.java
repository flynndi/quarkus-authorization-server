package io.quarkiverse.authorization.server.deployment;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.client.registration.ClientRegistrationScopeValidator;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

class ClientRegistrationScopeValidatorTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(jar -> ClientRegistrationTestApplication.baseApplication(jar)
                    .addClasses(ScopePolicy.class, PolicyRequestProbe.class, PolicyRequestProbe.Observations.class))
            .overrideConfigKey("quarkus.authorization-server.client-registration.enabled", "true");

    @Inject
    OAuth2AuthorizationService authorizations;
    @Inject
    RegisteredClientRepository clients;
    @Inject
    PolicyRequestProbe.Observations observations;

    @ParameterizedTest
    @ValueSource(strings = { "/clients", "/oauth2/register" })
    void scopePolicyIsSharedWithoutReplacingEitherRequestValidator(String endpoint) {
        observations.clear();
        ClientRegistrationScopeValidatorTest.register(endpoint, initial(), Map.of("grant_types", List.of("client_credentials"),
                "redirect_uris", List.of("https://rp.example/callback"), "scope", "message.read"))
                .then().statusCode(201).body("scope", org.hamcrest.Matchers.equalTo("message.read"));
        observations.assertReleased(List.of("scope-policy"));
        observations.clear();
        ClientRegistrationScopeValidatorTest.register(endpoint, initial(), Map.of("grant_types", List.of("client_credentials"),
                "redirect_uris", List.of("https://rp.example/callback")))
                .then().statusCode(201);
        observations.assertReleased(List.of("scope-policy"));
    }

    @ParameterizedTest
    @ValueSource(strings = { "/clients", "/oauth2/register" })
    void rejectedScopesDoNotConsumeInitialTokens(String endpoint) {
        observations.clear();
        String token = initial();
        ClientRegistrationScopeValidatorTest.register(endpoint, token,
                Map.of("grant_types", List.of("client_credentials"), "redirect_uris", List.of("https://rp.example/callback"),
                        "scope", "admin"))
                .then().statusCode(400).body("error", org.hamcrest.Matchers.equalTo("invalid_scope"));
        Assertions.assertTrue(authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN).getAccessToken().isActive());
        observations.assertReleased(List.of("scope-policy"));
        observations.clear();
        // The application policy must not bypass reserved control-scope checks.
        ClientRegistrationScopeValidatorTest.register(endpoint, token,
                Map.of("grant_types", List.of("client_credentials"), "redirect_uris", List.of("https://rp.example/callback"),
                        "scope", "client.create"))
                .then().statusCode(400).body("error", org.hamcrest.Matchers.equalTo("invalid_client_metadata"));
        Assertions.assertTrue(observations.visits.isEmpty());
        Assertions.assertTrue(authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN).getAccessToken().isActive());
    }

    @ParameterizedTest
    @ValueSource(strings = { "/clients", "/oauth2/register" })
    void scopeOnlyCustomizationPreservesRedirectValidation(String endpoint) {
        observations.clear();
        String token = initial();
        for (String uri : List.of("//rp.example/callback", "javascript:alert(1)", "https://rp.example/callback#fragment")) {
            ClientRegistrationScopeValidatorTest.register(endpoint, token,
                    Map.of("redirect_uris", List.of(uri), "scope", "message.read"))
                    .then().statusCode(400).body("error", org.hamcrest.Matchers.equalTo("invalid_redirect_uri"));
        }
        Assertions.assertTrue(observations.visits.isEmpty());
        Assertions.assertTrue(authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN).getAccessToken().isActive());
    }

    @Test
    void scopeOnlyCustomizationPreservesLogoutAndJwkUriValidation() {
        observations.clear();
        String token = initial();
        for (Map<String, Object> metadata : List.<Map<String, Object>> of(
                Map.of("redirect_uris", List.of("https://rp.example/callback"), "scope", "message.read",
                        "post_logout_redirect_uris", List.of("https://rp.example/logout#fragment")),
                Map.of("redirect_uris", List.of("https://rp.example/callback"), "scope", "message.read",
                        "token_endpoint_auth_method", "private_key_jwt", "jwks_uri",
                        "http://localhost:8081/api/oauth2/jwks"))) {
            ClientRegistrationScopeValidatorTest.register("/clients", token, metadata)
                    .then().statusCode(400).body("error", org.hamcrest.Matchers.equalTo("invalid_client_metadata"));
        }
        Assertions.assertTrue(observations.visits.isEmpty());
        Assertions.assertTrue(authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN).getAccessToken().isActive());
    }

    private String initial() {
        String token = UUID.randomUUID().toString();
        var client = clients.findByClientId("bootstrap");
        var scopes = Set.of("client.create");
        authorizations.save(OAuth2Authorization.withRegisteredClient(client)
                .principalName(client.getClientId())
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(scopes)
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token,
                        Instant.now(), Instant.now().plusSeconds(300), scopes))
                .build());
        return token;
    }

    private static Response register(String endpoint, String token, Map<String, Object> metadata) {
        return RestAssured.given().auth().oauth2(token).contentType(ContentType.JSON).body(metadata).post(endpoint);
    }

    @Singleton
    public static class ScopePolicy implements ClientRegistrationScopeValidator {
        @Inject
        PolicyRequestProbe request;

        @Override
        public void validate(Set<String> scopes) {
            request.visit("scope-policy");
            Assertions.assertThrows(UnsupportedOperationException.class, () -> scopes.add("injected"));
            // Deliberately allow the reserved scope here: the mandatory service check must still reject it.
            if (!Set.of("message.read", "client.create").containsAll(scopes)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
            }
        }
    }
}
