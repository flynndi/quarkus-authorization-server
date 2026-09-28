package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.grant.authorizationcode.OAuth2AuthorizationConsentPage;
import io.quarkiverse.authorization.server.grant.devicecode.OAuth2DeviceVerificationPage;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.token.Jwt;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

class DefaultBeanOverridesTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar
                    .addClasses(CustomRegisteredClientRepository.class,
                            CustomOAuth2AuthorizationService.class,
                            CustomOAuth2AuthorizationConsentService.class,
                            CustomAuthorizationConsentPage.class,
                            CustomDeviceVerificationPage.class,
                            CustomOAuth2TokenGenerator.class,
                            CustomOAuth2TokenCustomizer.class,
                            ResourceOwnerIdentityProvider.class)
                    .addAsResource(new StringAsset(
                            "quarkus.authorization-server.issuer=https://issuer.example.com"),
                            "application.properties"));

    @Inject
    RegisteredClientRepository registeredClientRepository;

    @Inject
    OAuth2AuthorizationService authorizationService;

    @Inject
    OAuth2AuthorizationConsentService authorizationConsentService;

    @Inject
    OAuth2AuthorizationConsentPage authorizationConsentPage;

    @Inject
    OAuth2DeviceVerificationPage deviceVerificationPage;

    @Inject
    OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    @Inject
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer;

    @Test
    void applicationBeansReplaceAllExtensionDefaults() {
        assertInstanceOf(CustomRegisteredClientRepository.class, this.registeredClientRepository);
        assertInstanceOf(CustomOAuth2AuthorizationService.class, this.authorizationService);
        assertInstanceOf(CustomOAuth2AuthorizationConsentService.class, this.authorizationConsentService);
        assertInstanceOf(CustomAuthorizationConsentPage.class, this.authorizationConsentPage);
        assertInstanceOf(CustomDeviceVerificationPage.class, this.deviceVerificationPage);
        assertInstanceOf(CustomOAuth2TokenGenerator.class, this.tokenGenerator);
        assertInstanceOf(CustomOAuth2TokenCustomizer.class, this.tokenCustomizer);

        given()
                .auth().preemptive().basic("override-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password")
                .when().post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("access_token", equalTo("custom-access-token"));

        assertTrue(CustomRegisteredClientRepository.clientLookupUsed);
        assertTrue(CustomOAuth2TokenGenerator.generateUsed);
        assertNotNull(CustomOAuth2AuthorizationService.savedAuthorization);
    }

    @Test
    void clientCredentialsUsesCodeRegisteredClientAndApplicationServicesWithoutOidc() {
        assertTrue(this.registeredClientRepository.findByClientId("override-client").getRedirectUris().isEmpty());
        given().auth().preemptive().basic("override-client", "client-secret").contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials").formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200)
                .body("access_token", equalTo("custom-access-token"))
                .body("scope", equalTo("message.read"));

        assertEquals(AuthorizationGrantType.CLIENT_CREDENTIALS,
                CustomOAuth2AuthorizationService.savedAuthorization.getAuthorizationGrantType());
        assertEquals("override-client", CustomOAuth2AuthorizationService.savedAuthorization.getPrincipalName());
        assertEquals(Set.of("message.read"), CustomOAuth2AuthorizationService.savedAuthorization.getAuthorizedScopes());
        given().get("/.well-known/openid-configuration").then().statusCode(404);
    }

    @Singleton
    public static class CustomRegisteredClientRepository implements RegisteredClientRepository {

        private static final RegisteredClient REGISTERED_CLIENT = RegisteredClient.withId("override-registration")
                .clientId("override-client")
                .clientSecret("$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("message.read")
                .build();

        static volatile boolean clientLookupUsed;

        @Override
        public void save(RegisteredClient registeredClient) {
        }

        @Override
        public RegisteredClient findById(String id) {
            return REGISTERED_CLIENT.getId().equals(id) ? REGISTERED_CLIENT : null;
        }

        @Override
        public RegisteredClient findByClientId(String clientId) {
            clientLookupUsed = true;
            return REGISTERED_CLIENT.getClientId().equals(clientId) ? REGISTERED_CLIENT : null;
        }
    }

    @Singleton
    public static class CustomOAuth2AuthorizationService implements OAuth2AuthorizationService {

        static volatile OAuth2Authorization savedAuthorization;

        @Override
        public void save(OAuth2Authorization authorization) {
            savedAuthorization = authorization;
        }

        @Override
        public void remove(OAuth2Authorization authorization) {
        }

        @Override
        public OAuth2Authorization findById(String id) {
            return null;
        }

        @Override
        public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
            return null;
        }
    }

    @Singleton
    public static class CustomOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

        @Override
        public void save(OAuth2AuthorizationConsent authorizationConsent) {
        }

        @Override
        public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        }

        @Override
        public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
            return null;
        }
    }

    @Singleton
    public static class CustomAuthorizationConsentPage implements OAuth2AuthorizationConsentPage {

        @Override
        public void displayConsent(RoutingContext context, String clientId, SecurityIdentity principal,
                Set<String> requestedScopes, Set<String> authorizedScopes, String state) {
        }
    }

    @Singleton
    public static class CustomDeviceVerificationPage implements OAuth2DeviceVerificationPage {

        @Override
        public void displayVerification(RoutingContext context) {
        }

        @Override
        public void displayConfirmation(RoutingContext context, String clientId, SecurityIdentity principal,
                Set<String> requestedScopes, Set<String> authorizedScopes, String userCode, String state) {
        }

        @Override
        public void displaySuccess(RoutingContext context, String clientId) {
        }

        @Override
        public void displayError(RoutingContext context, OAuth2Error error) {
        }
    }

    @Singleton
    public static class CustomOAuth2TokenGenerator implements OAuth2TokenGenerator<OAuth2Token> {

        static volatile boolean generateUsed;

        @Override
        public OAuth2Token generate(OAuth2TokenContext context) {
            generateUsed = true;
            Instant issuedAt = Instant.now();
            return new Jwt("custom-access-token", issuedAt, issuedAt.plusSeconds(300),
                    Map.of("alg", "custom"), Map.of("sub", context.getPrincipal().getPrincipal().getName()));
        }
    }

    @Singleton
    public static class CustomOAuth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

        @Override
        public void customize(JwtEncodingContext context) {
            context.getClaims().claim("custom", true);
        }
    }

    @Singleton
    public static class ResourceOwnerIdentityProvider implements IdentityProvider<UsernamePasswordAuthenticationRequest> {

        @Override
        public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
            return UsernamePasswordAuthenticationRequest.class;
        }

        @Override
        public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
                AuthenticationRequestContext context) {
            if (!"resource-owner".equals(request.getUsername())
                    || !Arrays.equals("resource-owner-password".toCharArray(), request.getPassword().getPassword())) {
                return Uni.createFrom().failure(new AuthenticationFailedException());
            }
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal(request.getUsername()))
                    .build());
        }
    }
}
