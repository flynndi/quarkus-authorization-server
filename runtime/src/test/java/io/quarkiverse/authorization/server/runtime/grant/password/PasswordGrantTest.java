package io.quarkiverse.authorization.server.runtime.grant.password;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.grant.password.PasswordGrantRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcParameterNames;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.grant.password.web.PasswordIdentityAuthenticator;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.Jwt;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

class PasswordGrantTest {

    @Test
    void rejectsAnonymousIdentityBeforeTokenGeneration() {
        SecurityIdentity anonymous = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("named-anonymous"))
                .setAnonymous(true)
                .build();
        var tokens = new RecordingTokenGenerator();
        var flow = provider(
                new RecordingIdentityProviderManager(Uni.createFrom().item(anonymous)),
                tokens);
        var request = passwordAuthentication(
                clientIdentity(passwordClient(Set.of("message.read"))),
                Set.of(),
                "resource-owner-password");
        var failure = assertThrows(
                OAuth2AuthenticationException.class,
                () -> authenticate(flow, request).await().indefinitely());
        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, failure.getError().getErrorCode());
        assertNull(tokens.context);
    }

    @Test
    void authenticatesResourceOwnerWithoutReplacingClientPrincipal() {
        SecurityIdentity resourceOwner = QuarkusSecurityIdentity.builder(identity("resource-owner"))
                .addAttribute("tenant", "customizer-tenant")
                .build();
        RecordingIdentityProviderManager identityProviderManager = new RecordingIdentityProviderManager(
                Uni.createFrom().item(resourceOwner));
        RecordingTokenGenerator tokenGenerator = new RecordingTokenGenerator();
        PasswordFlow provider = provider(identityProviderManager, tokenGenerator);
        SecurityIdentity clientPrincipal = clientIdentity(passwordClient(Set.of("message.read", "message.write")));
        PasswordGrantRequest authentication = new PasswordGrantRequest(
                clientPrincipal,
                "resource-owner",
                "resource-owner-password",
                Map.of("tenant", "internal"),
                Set.of());

        TokenIssuanceResult result = authenticate(provider, authentication).await().indefinitely();

        assertSame(resourceOwner, tokenGenerator.context.getPrincipal());
        assertEquals(
                "customizer-tenant", tokenGenerator.context.getPrincipal().getAttribute("tenant"));
        assertSame(clientPrincipal, result.getPrincipal());
        assertSame(clientPrincipal, authentication.getClientPrincipal());
        assertEquals(
                "resource-owner", tokenGenerator.context.getPrincipal().getPrincipal().getName());
        assertEquals(
                "messaging-client", authentication.getClientPrincipal().getPrincipal().getName());
        assertEquals(Set.of("message.read", "message.write"), result.getAccessToken().getScopes());
        assertTrue(identityProviderManager.passwordMatchedBeforeCompletion);
        assertEquals("internal", identityProviderManager.request.getAttribute("tenant"));
        assertArrayEquals(
                new char["resource-owner-password".length()],
                identityProviderManager.request.getPassword().getPassword());
    }

    @Test
    void acceptsExplicitRegisteredScopeSubset() {
        PasswordFlow provider = provider(
                new RecordingIdentityProviderManager(
                        Uni.createFrom().item(identity("resource-owner"))));
        PasswordGrantRequest authentication = passwordAuthentication(
                clientIdentity(passwordClient(Set.of("message.read", "message.write"))),
                Set.of("message.read"),
                "resource-owner-password");

        TokenIssuanceResult result = authenticate(provider, authentication).await().indefinitely();

        assertEquals(Set.of("message.read"), result.getAccessToken().getScopes());
    }

    @Test
    void savesAuthorizationBeforeReturningAccessToken() {
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();
        SecurityIdentity resourceOwner = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("resource-owner"))
                .addRole("user")
                .addCredential(
                        new PasswordCredential("resource-owner-password".toCharArray()))
                .addAttribute("request-only", "not-persisted")
                .build();
        PasswordFlow provider = provider(
                new RecordingIdentityProviderManager(Uni.createFrom().item(resourceOwner)),
                new RecordingTokenGenerator(),
                authorizationService);
        PasswordGrantRequest authentication = passwordAuthentication(
                clientIdentity(passwordClient(Set.of("message.read"))),
                Set.of(),
                "resource-owner-password");

        TokenIssuanceResult result = authenticate(provider, authentication).await().indefinitely();

        OAuth2Authorization authorization = authorizationService.findByToken(
                result.getAccessToken().getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
        assertNotNull(authorization);
        assertEquals("messaging-client-registration", authorization.getRegisteredClientId());
        assertEquals("resource-owner", authorization.getPrincipalName());
        assertEquals(AuthorizationGrantType.PASSWORD, authorization.getAuthorizationGrantType());
        assertEquals(
                OAuth2TokenFormat.SELF_CONTAINED.getValue(),
                authorization.getAccessToken().getMetadata(OAuth2TokenFormat.class.getName()));
        assertEquals(Set.of("message.read"), authorization.getAuthorizedScopes());
        SecurityIdentity authorizedPrincipal = authorization.getAttribute(SecurityIdentity.class.getName());
        assertNotNull(authorizedPrincipal);
        assertEquals("resource-owner", authorizedPrincipal.getPrincipal().getName());
        assertEquals(Set.of("user"), authorizedPrincipal.getRoles());
        assertTrue(authorizedPrincipal.getCredentials().isEmpty());
        assertTrue(authorizedPrincipal.getAttributes().isEmpty());
    }

    @Test
    void issuesAndPersistsRefreshTokenWhenClientDeclaresRefreshTokenGrant() {
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();
        RecordingTokenGenerator tokenGenerator = new RecordingTokenGenerator();
        PasswordFlow provider = provider(
                new RecordingIdentityProviderManager(
                        Uni.createFrom().item(identity("resource-owner"))),
                tokenGenerator,
                authorizationService);
        RegisteredClient registeredClient = RegisteredClient.withId("messaging-client-registration")
                .clientId("messaging-client")
                .clientSecret("client-secret")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("message.read")
                .build();

        TokenIssuanceResult result = authenticate(
                provider,
                passwordAuthentication(
                        clientIdentity(registeredClient),
                        Set.of(),
                        "resource-owner-password"))
                .await()
                .indefinitely();

        assertNotNull(result.getRefreshToken());
        assertEquals(2, tokenGenerator.invocations);
        OAuth2Authorization authorization = authorizationService.findByToken(
                result.getRefreshToken().getTokenValue(), OAuth2TokenType.REFRESH_TOKEN);
        assertNotNull(authorization);
        assertEquals(result.getRefreshToken(), authorization.getRefreshToken().getToken());
    }

    @Test
    void doesNotGenerateRefreshTokenWhenClientDoesNotDeclareRefreshTokenGrant() {
        RecordingTokenGenerator tokenGenerator = new RecordingTokenGenerator();
        PasswordFlow provider = provider(
                new RecordingIdentityProviderManager(
                        Uni.createFrom().item(identity("resource-owner"))),
                tokenGenerator);

        TokenIssuanceResult result = authenticate(
                provider,
                passwordAuthentication(
                        clientIdentity(passwordClient(Set.of("message.read"))),
                        Set.of(),
                        "resource-owner-password"))
                .await()
                .indefinitely();

        assertNull(result.getRefreshToken());
        assertEquals(1, tokenGenerator.invocations);
    }

    @Test
    void doesNotSaveAccessTokenWhenRefreshTokenGenerationFails() {
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();
        OAuth2TokenGenerator<OAuth2Token> tokenGenerator = context -> {
            if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                return null;
            }
            Instant issuedAt = Instant.now();
            return new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "access-token",
                    issuedAt,
                    issuedAt.plusSeconds(300),
                    context.getAuthorizedScopes());
        };
        PasswordFlow provider = provider(
                new RecordingIdentityProviderManager(
                        Uni.createFrom().item(identity("resource-owner"))),
                tokenGenerator,
                authorizationService);
        RegisteredClient registeredClient = RegisteredClient.withId("messaging-client-registration")
                .clientId("messaging-client")
                .clientSecret("client-secret")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("message.read")
                .build();

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> authenticate(
                        provider,
                        passwordAuthentication(
                                clientIdentity(registeredClient),
                                Set.of(),
                                "resource-owner-password"))
                        .await()
                        .indefinitely());

        assertEquals(OAuth2ErrorCodes.SERVER_ERROR, exception.getError().getErrorCode());
        assertNull(authorizationService.findByToken("access-token", OAuth2TokenType.ACCESS_TOKEN));
    }

    @Test
    void rejectsClientWithoutPasswordGrant() {
        RegisteredClient registeredClient = RegisteredClient.withId("refresh-client-registration")
                .clientId("refresh-client")
                .clientSecret("client-secret")
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("message.read")
                .build();
        PasswordFlow provider = provider(
                new RecordingIdentityProviderManager(
                        Uni.createFrom().item(identity("resource-owner"))));
        PasswordGrantRequest authentication = passwordAuthentication(
                clientIdentity(registeredClient), Set.of(), "resource-owner-password");

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> authenticate(provider, authentication).await().indefinitely());

        assertEquals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, exception.getError().getErrorCode());
    }

    @Test
    void rejectsMissingAuthenticatedClient() {
        PasswordFlow provider = provider(
                new RecordingIdentityProviderManager(
                        Uni.createFrom().item(identity("resource-owner"))));
        PasswordGrantRequest authentication = passwordAuthentication(
                identity("unregistered-client"), Set.of(), "resource-owner-password");

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> authenticate(provider, authentication).await().indefinitely());

        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, exception.getError().getErrorCode());
    }

    @Test
    void mapsResourceOwnerAuthenticationFailureToInvalidGrant() {
        PasswordFlow provider = provider(
                new RecordingIdentityProviderManager(
                        Uni.createFrom().failure(new AuthenticationFailedException())));
        PasswordGrantRequest authentication = passwordAuthentication(
                clientIdentity(passwordClient(Set.of("message.read"))),
                Set.of(),
                "wrong-password");

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> authenticate(provider, authentication).await().indefinitely());

        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, exception.getError().getErrorCode());
    }

    @Test
    void mapsMissingResourceOwnerIdentityToInvalidGrant() {
        PasswordFlow provider = provider(new RecordingIdentityProviderManager(Uni.createFrom().nullItem()));
        PasswordGrantRequest authentication = passwordAuthentication(
                clientIdentity(passwordClient(Set.of("message.read"))),
                Set.of(),
                "resource-owner-password");

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> authenticate(provider, authentication).await().indefinitely());

        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, exception.getError().getErrorCode());
    }

    @Test
    void rejectsScopeOutsideRegisteredScopes() {
        PasswordFlow provider = provider(
                new RecordingIdentityProviderManager(
                        Uni.createFrom().item(identity("resource-owner"))));
        PasswordGrantRequest authentication = passwordAuthentication(
                clientIdentity(passwordClient(Set.of("message.read"))),
                Set.of("message.write"),
                "resource-owner-password");

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> authenticate(provider, authentication).await().indefinitely());

        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, exception.getError().getErrorCode());
    }

    @Test
    void issuesAndPersistsIdTokenFromExplicitOrOmittedScopes() {
        RegisteredClient client = RegisteredClient.from(passwordClient(Set.of("openid", "message.read")))
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();
        SecurityIdentity clientPrincipal = clientIdentity(client);
        for (Set<String> requestedScopes : List.of(Set.of("openid"), Set.<String> of())) {
            InMemoryOAuth2AuthorizationService service = new InMemoryOAuth2AuthorizationService();
            RecordingTokenGenerator generator = new RecordingTokenGenerator();
            PasswordFlow provider = provider(
                    new RecordingIdentityProviderManager(
                            Uni.createFrom().item(identity("resource-owner"))),
                    generator,
                    service);

            TokenIssuanceResult result = authenticate(
                    provider,
                    passwordAuthentication(
                            clientPrincipal,
                            requestedScopes,
                            "resource-owner-password"))
                    .await()
                    .indefinitely();

            assertEquals(
                    Map.of(OidcParameterNames.ID_TOKEN, "id-token"),
                    result.getAdditionalParameters());
            assertSame(clientPrincipal, result.getPrincipal());
            assertEquals(3, generator.invocations);
            assertEquals(OidcParameterNames.ID_TOKEN, generator.context.getTokenType().getValue());
            assertEquals(
                    AuthorizationGrantType.PASSWORD, generator.context.getAuthorizationGrantType());
            assertEquals(
                    "resource-owner", generator.context.getPrincipal().getPrincipal().getName());
            assertEquals(
                    result.getAccessToken(),
                    generator.context.getAuthorization().getAccessToken().getToken());
            assertEquals(
                    result.getRefreshToken(),
                    generator.context.getAuthorization().getRefreshToken().getToken());
            OAuth2Authorization saved = service.findByToken(
                    "id-token", new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
            assertNotNull(saved);
            assertEquals(
                    requestedScopes.isEmpty() ? client.getScopes() : requestedScopes,
                    saved.getAuthorizedScopes());
            assertEquals(saved.getAuthorizedScopes(), result.getAccessToken().getScopes());
            assertEquals("resource-owner", saved.getPrincipalName());
            assertEquals(
                    "resource-owner", saved.getToken(OidcIdToken.class).getToken().getSubject());
            assertEquals(
                    saved.getToken(OidcIdToken.class).getToken().getClaims(),
                    saved.getToken(OidcIdToken.class).getClaims());
            assertSame(saved, service.findByToken("access-token", OAuth2TokenType.ACCESS_TOKEN));
            assertSame(saved, service.findByToken("refresh-token", OAuth2TokenType.REFRESH_TOKEN));
        }
    }

    @Test
    void doesNotGenerateIdTokenWhenRequestedScopesExcludeOpenid() {
        RecordingTokenGenerator generator = new RecordingTokenGenerator();
        PasswordFlow provider = provider(
                new RecordingIdentityProviderManager(
                        Uni.createFrom().item(identity("resource-owner"))),
                generator);
        SecurityIdentity clientPrincipal = clientIdentity(passwordClient(Set.of("openid", "message.read")));

        TokenIssuanceResult result = authenticate(
                provider,
                passwordAuthentication(
                        clientPrincipal,
                        Set.of("message.read"),
                        "resource-owner-password"))
                .await()
                .indefinitely();

        assertEquals(Set.of("message.read"), result.getAccessToken().getScopes());
        assertTrue(result.getAdditionalParameters().isEmpty());
        assertEquals(1, generator.invocations);
    }

    @Test
    void invalidIdTokenGeneratorResultsDoNotSavePartialTokens() {
        RegisteredClient client = RegisteredClient.from(passwordClient(Set.of("openid")))
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();
        for (boolean wrongType : List.of(false, true)) {
            InMemoryOAuth2AuthorizationService service = new InMemoryOAuth2AuthorizationService();
            RecordingTokenGenerator generator = new RecordingTokenGenerator();
            RecordingIdentityProviderManager identityProviderManager = new RecordingIdentityProviderManager(
                    Uni.createFrom().item(identity("resource-owner")));
            PasswordFlow provider = provider(
                    identityProviderManager,
                    context -> {
                        if (OidcParameterNames.ID_TOKEN.equals(
                                context.getTokenType().getValue())) {
                            assertNotNull(context.getAuthorization().getAccessToken());
                            assertNotNull(context.getAuthorization().getRefreshToken());
                            return wrongType
                                    ? context.getAuthorization().getAccessToken().getToken()
                                    : null;
                        }
                        return generator.generate(context);
                    },
                    service);

            OAuth2AuthenticationException error = assertThrows(
                    OAuth2AuthenticationException.class,
                    () -> authenticate(
                            provider,
                            passwordAuthentication(
                                    clientIdentity(client),
                                    Set.of("openid"),
                                    "resource-owner-password"))
                            .await()
                            .indefinitely());

            assertEquals(OAuth2ErrorCodes.SERVER_ERROR, error.getError().getErrorCode());
            assertNull(service.findByToken("access-token", OAuth2TokenType.ACCESS_TOKEN));
            assertNull(service.findByToken("refresh-token", OAuth2TokenType.REFRESH_TOKEN));
            assertArrayEquals(
                    new char["resource-owner-password".length()],
                    identityProviderManager.request.getPassword().getPassword());
        }
    }

    private static PasswordGrantRequest passwordAuthentication(
            SecurityIdentity clientPrincipal, Set<String> scopes, String password) {
        return new PasswordGrantRequest(
                clientPrincipal, "resource-owner", password, Map.of(), scopes);
    }

    @Test
    void resourceOwnerAuthenticationIsDeferredAndUsesFreshCredentialsPerSubscription() {
        RecordingIdentityProviderManager manager = new RecordingIdentityProviderManager(
                Uni.createFrom().item(identity("alice")));
        PasswordFlow provider = provider(manager);
        var authentication = passwordAuthentication(
                clientIdentity(passwordClient(Set.of("message.read"))),
                Set.of(),
                "resource-owner-password");
        var pending = provider.authenticateResourceOwner(authentication);
        assertNull(manager.request);
        pending.await().indefinitely();
        char[] first = manager.request.getPassword().getPassword();
        assertArrayEquals(new char[first.length], first);
        pending.await().indefinitely();
        char[] second = manager.request.getPassword().getPassword();
        assertNotSame(first, second);
        assertTrue(manager.passwordMatchedBeforeCompletion);
        assertArrayEquals(new char[second.length], second);
    }

    @Test
    void cancellingResourceOwnerAuthenticationErasesCredentials() {
        RecordingIdentityProviderManager manager = new RecordingIdentityProviderManager(Uni.createFrom().nothing());
        PasswordFlow provider = provider(manager);
        var pending = provider.authenticateResourceOwner(
                passwordAuthentication(
                        clientIdentity(passwordClient(Set.of("message.read"))),
                        Set.of(),
                        "resource-owner-password"));
        var subscription = pending.subscribe().with(ignored -> {
        }, ignored -> {
        });
        assertTrue(manager.passwordMatchedBeforeCompletion);
        subscription.cancel();
        char[] password = manager.request.getPassword().getPassword();
        assertArrayEquals(new char[password.length], password);
    }

    @Test
    void synchronousIdentityProviderFailureIsMappedAndCredentialsAreErased() {
        var credentials = new java.util.concurrent.atomic.AtomicReference<char[]>();
        IdentityProviderManager manager = new IdentityProviderManager() {
            @Override
            public Uni<SecurityIdentity> authenticate(AuthenticationRequest request) {
                credentials.set(
                        ((UsernamePasswordAuthenticationRequest) request)
                                .getPassword()
                                .getPassword());
                throw new AuthenticationFailedException();
            }

            @Override
            public SecurityIdentity authenticateBlocking(AuthenticationRequest request) {
                throw new AssertionError("Blocking authentication must not be used");
            }
        };
        PasswordFlow provider = provider(manager);
        var pending = provider.authenticateResourceOwner(
                passwordAuthentication(
                        clientIdentity(passwordClient(Set.of("message.read"))),
                        Set.of(),
                        "resource-owner-password"));
        var failure = assertThrows(
                OAuth2AuthenticationException.class, () -> pending.await().indefinitely());
        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, failure.getError().getErrorCode());
        assertArrayEquals(new char[credentials.get().length], credentials.get());
    }

    private static Uni<TokenIssuanceResult> authenticate(
            PasswordFlow provider, PasswordGrantRequest authentication) {
        return provider.authenticateResourceOwner(authentication)
                .onItem()
                .transform(identity -> provider.issueTokens(authentication, identity));
    }

    private static PasswordFlow provider(IdentityProviderManager identityProviderManager) {
        return provider(identityProviderManager, new RecordingTokenGenerator());
    }

    private static PasswordFlow provider(
            IdentityProviderManager identityProviderManager,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        return provider(
                identityProviderManager, tokenGenerator, new InMemoryOAuth2AuthorizationService());
    }

    private static PasswordFlow provider(
            IdentityProviderManager identityProviderManager,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            OAuth2AuthorizationService authorizationService) {
        return new PasswordFlow(
                new PasswordGrant(
                        tokenGenerator,
                        new DefaultAuthorizationServerContext(AuthorizationServerSettings.builder()
                                .issuer("https://issuer.example.com")
                                .build()),
                        authorizationService),
                new PasswordIdentityAuthenticator(identityProviderManager));
    }

    private record PasswordFlow(PasswordGrant grant, PasswordIdentityAuthenticator identities) {
        Uni<SecurityIdentity> authenticateResourceOwner(PasswordGrantRequest request) {
            return Uni.createFrom()
                    .deferred(
                            () -> {
                                grant.validateClient(request);
                                return identities.authenticate(request, null);
                            });
        }

        TokenIssuanceResult issueTokens(PasswordGrantRequest request, SecurityIdentity identity) {
            return grant.issueTokens(request, identity);
        }
    }

    private static RegisteredClient passwordClient(Set<String> scopes) {
        RegisteredClient.Builder builder = RegisteredClient.withId("messaging-client-registration")
                .clientId("messaging-client")
                .clientSecret("client-secret")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD);
        scopes.forEach(builder::scope);
        return builder.build();
    }

    private static SecurityIdentity clientIdentity(RegisteredClient registeredClient) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(registeredClient.getClientId()))
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                        registeredClient)
                .build();
    }

    private static SecurityIdentity identity(String principalName) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(principalName))
                .build();
    }

    private static final class RecordingIdentityProviderManager implements IdentityProviderManager {

        private final Uni<SecurityIdentity> result;
        private UsernamePasswordAuthenticationRequest request;
        private boolean passwordMatchedBeforeCompletion;

        private RecordingIdentityProviderManager(Uni<SecurityIdentity> result) {
            this.result = result;
        }

        @Override
        public Uni<SecurityIdentity> authenticate(AuthenticationRequest request) {
            this.request = (UsernamePasswordAuthenticationRequest) request;
            this.passwordMatchedBeforeCompletion = Arrays.equals(
                    "resource-owner-password".toCharArray(),
                    this.request.getPassword().getPassword())
                    || Arrays.equals(
                            "wrong-password".toCharArray(),
                            this.request.getPassword().getPassword());
            return this.result;
        }

        @Override
        public SecurityIdentity authenticateBlocking(AuthenticationRequest request) {
            throw new UnsupportedOperationException();
        }
    }

    private static final class RecordingTokenGenerator
            implements OAuth2TokenGenerator<OAuth2Token> {

        private OAuth2TokenContext context;
        private int invocations;

        @Override
        public OAuth2Token generate(OAuth2TokenContext context) {
            this.context = context;
            this.invocations++;
            Instant issuedAt = Instant.now();
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                return new Jwt(
                        "id-token",
                        issuedAt,
                        issuedAt.plusSeconds(1800),
                        Map.of("alg", "RS256"),
                        Map.of(
                                "sub",
                                context.getPrincipal().getPrincipal().getName(),
                                "aud",
                                List.of(context.getRegisteredClient().getClientId())));
            }
            if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                return new OAuth2RefreshToken(
                        "refresh-token", issuedAt, issuedAt.plusSeconds(3600));
            }
            return new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "access-token",
                    issuedAt,
                    issuedAt.plusSeconds(300),
                    context.getAuthorizedScopes());
        }
    }
}
