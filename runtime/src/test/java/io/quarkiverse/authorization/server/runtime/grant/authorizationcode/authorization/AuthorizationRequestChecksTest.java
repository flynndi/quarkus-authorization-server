package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequest;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestContext;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class AuthorizationRequestChecksTest {

    private static final SecurityIdentity PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("resource-owner"))
            .build();

    private final AuthorizationRequestChecks validator = new AuthorizationRequestChecks();

    @Test
    void acceptsExactRedirectUriAndAllowedScopes() {
        RegisteredClient registeredClient = registeredClient(
                Set.of("https://client.example.com/callback"),
                Set.of("message.read", "message.write"));

        this.validator.validate(
                context(
                        request("https://client.example.com/callback", Set.of("message.read")),
                        registeredClient));
    }

    @Test
    void acceptsOmittedRedirectUriOnlyForSingleRegisteredUri() {
        RegisteredClient registeredClient = registeredClient(
                Set.of("https://client.example.com/callback"), Set.of("message.read"));

        this.validator.validate(context(request(null, Set.of("message.read")), registeredClient));

        RegisteredClient multipleRedirectUris = registeredClient(
                Set.of(
                        "https://client.example.com/callback",
                        "https://client.example.com/other"),
                Set.of("message.read"));
        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> this.validator.validate(
                        context(
                                request(null, Set.of("message.read")),
                                multipleRedirectUris)));
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertNull(exception.getRedirect());
    }

    @Test
    void neverRedirectsAnInvalidRedirectUriError() {
        RegisteredClient registeredClient = registeredClient(
                Set.of("https://client.example.com/callback"), Set.of("message.read"));

        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> this.validator.validate(
                        context(
                                request(
                                        "https://attacker.example.com/callback",
                                        Set.of("message.read")),
                                registeredClient)));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals("OAuth 2.0 Parameter: redirect_uri", exception.getError().getDescription());
        assertNull(exception.getRedirect());
    }

    @Test
    void redirectsInvalidScopeToPreviouslyValidatedRedirectUri() {
        RegisteredClient registeredClient = registeredClient(
                Set.of("https://client.example.com/callback"), Set.of("message.read"));

        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> this.validator.validate(
                        context(
                                request(
                                        "https://client.example.com/callback",
                                        Set.of("message.write")),
                                registeredClient)));

        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, exception.getError().getErrorCode());
        assertEquals("https://client.example.com/callback", exception.getRedirect().uri());
    }

    @Test
    void allowsEphemeralPortForLoopbackRedirectUriOnly() {
        RegisteredClient registeredClient = registeredClient(Set.of("http://127.0.0.1:8080/callback"), Set.of("message.read"));

        this.validator.validate(
                context(
                        request("http://127.0.0.1:49152/callback", Set.of("message.read")),
                        registeredClient));

        assertThrows(
                AuthorizationRequestException.class,
                () -> this.validator.validate(
                        context(
                                request(
                                        "http://127.0.0.1:49152/other",
                                        Set.of("message.read")),
                                registeredClient)));
    }

    private static AuthorizationRequestContext context(
            AuthorizationRequest authentication, RegisteredClient registeredClient) {
        return AuthorizationRequestContext.with(authentication)
                .registeredClient(registeredClient)
                .build();
    }

    private static AuthorizationRequest request(String redirectUri, Set<String> scopes) {
        return new AuthorizationRequest(
                "https://issuer.example.com/oauth2/authorize",
                "messaging-client",
                PRINCIPAL,
                redirectUri,
                "state",
                scopes,
                Map.of());
    }

    private static RegisteredClient registeredClient(Set<String> redirectUris, Set<String> scopes) {
        RegisteredClient.Builder builder = RegisteredClient.withId("messaging-client")
                .clientId("messaging-client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        redirectUris.forEach(builder::redirectUri);
        scopes.forEach(builder::scope);
        return builder.build();
    }
}
