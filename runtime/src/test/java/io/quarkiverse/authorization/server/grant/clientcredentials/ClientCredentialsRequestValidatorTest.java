package io.quarkiverse.authorization.server.grant.clientcredentials;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTestSupport;
import io.quarkiverse.authorization.server.runtime.grant.clientcredentials.ClientCredentialsGrant;
import io.quarkiverse.authorization.server.runtime.grant.clientcredentials.NoopClientCredentialsRequestValidator;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class ClientCredentialsRequestValidatorTest {

    private final RegisteredClient registeredClient = RegisteredClient.withId("machine-registration")
            .clientId("machine-client")
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("message.read")
            .scope("message.write")
            .build();
    private final ClientCredentialsGrant grant = new ClientCredentialsGrant(
            new InMemoryOAuth2AuthorizationService(),
            context -> new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "access-token",
                    Instant.now(),
                    Instant.now().plusSeconds(60),
                    context.getAuthorizedScopes()),
            new DefaultAuthorizationServerContext(AuthorizationServerSettings.builder()
                    .issuer("https://issuer.example.com")
                    .build()),
            java.util.List.of(new NoopClientCredentialsRequestValidator()),
            DPoPTestSupport.binding());

    @Test
    void acceptsRegisteredScopes() {
        assertDoesNotThrow(() -> this.grant.issueTokens(authentication(Set.of("message.read"))));
        assertDoesNotThrow(
                () -> this.grant.issueTokens(authentication(this.registeredClient.getScopes())));
    }

    @Test
    void acceptsEmptyScopeWithoutAddingRegisteredScopes() {
        ClientCredentialsRequestContext context = context(Set.of());

        this.grant.issueTokens(context.request());

        assertTrue(context.request().getScopes().isEmpty());
    }

    @Test
    void rejectsUnregisteredScopes() {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.grant.issueTokens(
                        authentication(Set.of("message.read", "message.admin"))));

        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, exception.getError().getErrorCode());
    }

    @Test
    void contextRetainsValidatedRequestAndClient() {
        ClientCredentialsRequest request = authentication(Set.of());
        var context = new ClientCredentialsRequestContext(request, this.registeredClient);
        assertSame(request, context.request());
        assertSame(this.registeredClient, context.registeredClient());
    }

    @Test
    void contextRequiresRequestAndRegisteredClient() {
        assertThrows(
                NullPointerException.class,
                () -> new ClientCredentialsRequestContext(null, this.registeredClient));
        assertThrows(
                NullPointerException.class,
                () -> new ClientCredentialsRequestContext(authentication(Set.of()), null));
    }

    private ClientCredentialsRequestContext context(Set<String> scopes) {
        return new ClientCredentialsRequestContext(authentication(scopes), this.registeredClient);
    }

    private ClientCredentialsRequest authentication(Set<String> scopes) {
        return new ClientCredentialsRequest(
                QuarkusSecurityIdentity.builder()
                        .setPrincipal(new QuarkusPrincipal(this.registeredClient.getClientId()))
                        .addAttribute(
                                OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                                this.registeredClient)
                        .build(),
                scopes,
                Map.of());
    }
}
