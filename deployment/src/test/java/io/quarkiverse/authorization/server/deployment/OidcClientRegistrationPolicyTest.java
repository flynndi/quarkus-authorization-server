package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.ClientSecretEncoder;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.client.registration.RegistrationClientSettingsCustomizer;
import io.quarkiverse.authorization.server.client.registration.RegistrationTokenSettingsCustomizer;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.oidc.registration.ClientRegistrationMapper;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationRequestValidator;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationValidator;
import io.quarkiverse.authorization.server.oidc.registration.RegisteredClientMapper;
import io.quarkiverse.authorization.server.runtime.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import io.quarkiverse.authorization.server.runtime.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

class OidcClientRegistrationPolicyTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> ClientRegistrationTestApplication.baseApplication(jar)
                            .addClasses(
                                    Policies.class,
                                    PolicyRequestProbe.class,
                                    PolicyRequestProbe.Observations.class));

    @Inject
    OAuth2AuthorizationService authorizations;
    @Inject
    RegisteredClientRepository clients;
    @Inject
    PolicyRequestProbe.Observations observations;

    @org.junit.jupiter.api.BeforeEach
    void clearObservations() {
        this.observations.clear();
    }

    @Test
    void policiesControlRegistrationStorageConfigurationReadsAndClientAuthentication() {
        Response response = register(initial(), "RP", "https://rp.example/callback", "message.read")
                .then()
                .statusCode(201)
                .body("client_name", equalTo("RP-mapped"))
                .extract()
                .response();
        String clientId = response.path("client_id");
        var client = this.clients.findByClientId(clientId);
        assertEquals(Duration.ofSeconds(123), client.getTokenSettings().getAccessTokenTimeToLive());
        assertFalse(client.getClientSettings().isRequireAuthorizationConsent());
        assertTrue(BcryptUtil.matches(response.path("client_secret"), client.getClientSecret()));
        String registrationToken = response.path("registration_access_token");
        var access = this.authorizations
                .findByToken(registrationToken, OAuth2TokenType.ACCESS_TOKEN)
                .getAccessToken()
                .getToken();
        assertEquals(
                Duration.ofSeconds(123),
                Duration.between(access.getIssuedAt(), access.getExpiresAt()));
        this.observations.assertReleased(
                List.of(
                        "registration-validator",
                        "registration-converter",
                        "client-settings",
                        "token-settings",
                        "secret-encoder",
                        "registration-response"));
        given().auth()
                .oauth2(registrationToken)
                .queryParam("client_id", clientId)
                .get("/clients")
                .then()
                .statusCode(200)
                .body("client_name", equalTo("RP-mapped"));
        this.observations.assertReleased(List.of("registration-response"));
        given().auth()
                .preemptive()
                .basic(clientId, response.path("client_secret"))
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials")
                .formParam("scope", "message.read")
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("expires_in", equalTo(123));
    }

    @Test
    void applicationValidatorFailureReleasesScopeAndDoesNotConsumeInitialToken() {
        String initial = initial();
        register(initial, "deny", "https://rp.example/callback", "message.read")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_request"));
        assertTrue(
                this.authorizations
                        .findByToken(initial, OAuth2TokenType.ACCESS_TOKEN)
                        .getAccessToken()
                        .isActive());
        this.observations.assertReleased(List.of("registration-validator"));
    }

    @Test
    void customValidationAndConversionCanNormalizeInputsWhileRetainingDomainConstraints() {
        register(initial(), "custom-redirect", "https://rp.example/callback#custom", "message.read")
                .then()
                .statusCode(201)
                .body("redirect_uris[0]", equalTo("https://rp.example/callback"));
        register(initial(), "RP", "https://rp.example/callback#custom", "message.read")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_redirect_uri"));
        // Mandatory control scopes cannot be enabled by replacing the parameter validator.
        register(initial(), "custom-redirect", "https://rp.example/callback", "client.create")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_client_metadata"));
    }

    private String initial() {
        String value = UUID.randomUUID().toString();
        var bootstrap = this.clients.findByClientId("bootstrap");
        this.authorizations.save(
                OAuth2Authorization.withRegisteredClient(bootstrap)
                        .principalName(bootstrap.getClientId())
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .authorizedScopes(Set.of("client.create"))
                        .accessToken(
                                new OAuth2AccessToken(
                                        OAuth2AccessToken.TokenType.BEARER,
                                        value,
                                        Instant.now().minusSeconds(1),
                                        Instant.now().plusSeconds(300),
                                        Set.of("client.create")))
                        .build());
        return value;
    }

    private static Response register(String token, String name, String redirect, String scope) {
        return given().auth()
                .oauth2(token)
                .contentType(ContentType.JSON)
                .body(
                        Map.of(
                                "client_name",
                                name,
                                "redirect_uris",
                                List.of(redirect),
                                "grant_types",
                                List.of("client_credentials"),
                                "scope",
                                scope))
                .post("/clients");
    }

    @Singleton
    public static class Policies {
        @Inject
        PolicyRequestProbe request;
        @Inject
        io.vertx.ext.web.RoutingContext http;

        @Produces
        @Singleton
        OidcClientRegistrationRequestValidator validator() {
            OidcClientRegistrationRequestValidator defaults = OidcClientRegistrationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
                    .andThen(
                            OidcClientRegistrationValidator.DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR)
                    .andThen(
                            context -> {
                                var scopes = context.request()
                                        .getClientRegistration()
                                        .getScopes();
                                if (scopes != null
                                        && !Set.of("message.read").containsAll(scopes)) {
                                    throw new OAuth2AuthenticationException(
                                            OAuth2ErrorCodes.INVALID_SCOPE);
                                }
                            });
            return context -> {
                this.request.visit("registration-validator");
                org.junit.jupiter.api.Assertions.assertEquals(
                        "/api/clients", this.http.request().path());
                String name = context.request().getClientRegistration().getClientName();
                if (!"custom-redirect".equals(name)) {
                    defaults.validate(context);
                }
                if ("deny".equals(name)) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
                }
            };
        }

        @Produces
        @Singleton
        RegisteredClientMapper clientConverter(
                AuthorizationServerKeyManager keys,
                RegistrationClientSettingsCustomizer clientSettings,
                RegistrationTokenSettingsCustomizer tokenSettings) {
            var defaults = new OidcClientRegistrationRegisteredClientConverter(
                    keys.getSigningAlgorithms(),
                    clientSettings::customize,
                    tokenSettings::customize);
            return registration -> {
                this.request.visit("registration-converter");
                if ("custom-redirect".equals(registration.getClientName())) {
                    // Application policy accepts an input alias; the stored client still obeys
                    // domain URI constraints.
                    registration = OidcClientRegistration.withClaims(registration.getClaims())
                            .redirectUris(
                                    uris -> uris.replaceAll(uri -> uri.split("#", 2)[0]))
                            .build();
                }
                return defaults.convert(registration);
            };
        }

        @Produces
        @Singleton
        RegistrationClientSettingsCustomizer clientSettings() {
            return settings -> {
                this.request.visit("client-settings");
                settings.requireAuthorizationConsent(false);
            };
        }

        @Produces
        @Singleton
        RegistrationTokenSettingsCustomizer tokenSettings() {
            return settings -> {
                this.request.visit("token-settings");
                settings.accessTokenTimeToLive(Duration.ofSeconds(123));
            };
        }

        @Produces
        @Singleton
        ClientSecretEncoder encoder() {
            return secret -> {
                this.request.visit("secret-encoder");
                return BcryptUtil.bcryptHash(secret, 4);
            };
        }

        @Produces
        @Singleton
        ClientRegistrationMapper responseConverter() {
            return client -> {
                this.request.visit("registration-response");
                org.junit.jupiter.api.Assertions.assertEquals(
                        "/api/clients", this.http.request().path());
                return OidcClientRegistration.withClaims(
                        new RegisteredClientOidcClientRegistrationConverter()
                                .map(client)
                                .getClaims())
                        .clientName(client.getClientName() + "-mapped")
                        .build();
            };
        }
    }
}
