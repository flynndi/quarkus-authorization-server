package io.quarkiverse.authorization.server.runtime.client.registration;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import jakarta.enterprise.inject.Default;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.ClientSecretEncoder;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.client.registration.OAuth2ClientMetadataClaimNames;
import io.quarkiverse.authorization.server.client.registration.OAuth2ClientRegistrationRequest;
import io.quarkiverse.authorization.server.client.registration.OAuth2ClientRegistrationRequestValidator;
import io.quarkiverse.authorization.server.client.registration.RegistrationClientSettingsCustomizer;
import io.quarkiverse.authorization.server.client.registration.RegistrationTokenSettingsCustomizer;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerClientRegistrationConfig;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkus.arc.All;
import io.quarkus.security.credential.TokenCredential;

/** RFC 7591 registration; no registration access token or client configuration endpoint is created. */
@Singleton
public final class OAuth2ClientRegistrationService {
    private static final Set<ClientAuthenticationMethod> AUTHENTICATION_METHODS = Set.of(
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST,
            ClientAuthenticationMethod.NONE);
    private static final Set<AuthorizationGrantType> GRANTS = Set.of(AuthorizationGrantType.AUTHORIZATION_CODE,
            AuthorizationGrantType.CLIENT_CREDENTIALS, AuthorizationGrantType.REFRESH_TOKEN, AuthorizationGrantType.DEVICE_CODE,
            AuthorizationGrantType.TOKEN_EXCHANGE, AuthorizationGrantType.PASSWORD);
    private final RegisteredClientRepository clients;
    private final OAuth2AuthorizationService authorizations;
    private final ClientSecretEncoder encoder;
    private final AuthorizationServerClientRegistrationConfig config;
    private final AuthorizationServerOidcConfig oidc;
    private final OAuth2ClientRegistrationRequestValidator validator;
    private final List<RegistrationClientSettingsCustomizer> clientCustomizers;
    private final List<RegistrationTokenSettingsCustomizer> tokenCustomizers;
    private final SecureRandom random = new SecureRandom();

    @Inject
    public OAuth2ClientRegistrationService(RegisteredClientRepository clients, OAuth2AuthorizationService authorizations,
            ClientSecretEncoder encoder, AuthorizationServerClientRegistrationConfig config, AuthorizationServerOidcConfig oidc,
            OAuth2ClientRegistrationRequestValidator validator,
            @All @Default List<RegistrationClientSettingsCustomizer> clientCustomizers,
            @All @Default List<RegistrationTokenSettingsCustomizer> tokenCustomizers) {
        this.clients = clients;
        this.authorizations = authorizations;
        this.encoder = encoder;
        this.config = config;
        this.oidc = oidc;
        this.validator = validator;
        this.clientCustomizers = List.copyOf(clientCustomizers);
        this.tokenCustomizers = List.copyOf(tokenCustomizers);
    }

    public Map<String, Object> register(OAuth2ClientRegistrationRequest request) {
        OAuth2Authorization initial = null;
        // Open registration only permits absence of credentials. A supplied invalid token never falls back to anonymous.
        if (request.principal().isAnonymous() && request.principal().getCredential(TokenCredential.class) == null) {
            if (!this.config.openRegistrationAllowed())
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        } else {
            initial = RegistrationAccessTokens.getAccessTokenAuthorization(request.principal(), this.authorizations,
                    "client.create");
        }
        OAuth2ClientRegistrationService.validateCapabilities(request);
        if (!this.oidc.enabled() && request.scopes().contains("openid")) {
            throw OAuth2ClientRegistrationService.invalidMetadata(OAuth2ClientMetadataClaimNames.SCOPE);
        }
        this.validator.validate(request);
        var clientSettings = ClientSettings.builder().requireAuthorizationConsent(true);
        this.clientCustomizers.forEach(customizer -> customizer.customize(clientSettings));
        var tokenSettings = TokenSettings.builder();
        this.tokenCustomizers.forEach(customizer -> customizer.customize(tokenSettings));
        Instant issuedAt = Instant.now();
        var builder = RegisteredClient.withId(UUID.randomUUID().toString()).clientId(this.generateKey())
                .clientIdIssuedAt(issuedAt).clientAuthenticationMethod(request.authenticationMethod())
                .clientSettings(clientSettings.build()).tokenSettings(tokenSettings.build());
        if (request.clientName() != null)
            builder.clientName(request.clientName());
        request.grantTypes().forEach(builder::authorizationGrantType);
        request.redirectUris().forEach(builder::redirectUri);
        request.scopes().forEach(builder::scope);
        if (!ClientAuthenticationMethod.NONE.equals(request.authenticationMethod()))
            builder.clientSecret(this.generateKey());
        RegisteredClient client = builder.build();
        RegisteredClient storedClient = client;
        if (client.getClientSecret() != null) {
            String encoded = this.encoder.encode(client.getClientSecret());
            if (encoded == null || encoded.isBlank() || encoded.equals(client.getClientSecret())) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
            }
            storedClient = RegisteredClient.from(client).clientSecret(encoded).build();
        }
        Map<String, Object> response = OAuth2ClientRegistrationService.response(client);
        // Validate and prepare before writing; consume the initial token only after registration succeeds.
        this.clients.save(storedClient);
        if (initial != null)
            this.authorizations.save(RegistrationAccessTokens.invalidate(initial));
        return response;
    }

    private static void validateCapabilities(OAuth2ClientRegistrationRequest request) {
        if (!AUTHENTICATION_METHODS.contains(request.authenticationMethod())) {
            throw OAuth2ClientRegistrationService.invalidMetadata(OAuth2ClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD);
        }
        if (request.grantTypes().isEmpty() || !GRANTS.containsAll(request.grantTypes())
                || ClientAuthenticationMethod.NONE.equals(request.authenticationMethod())
                        && request.grantTypes().stream().anyMatch(grant -> !Set.of(AuthorizationGrantType.AUTHORIZATION_CODE,
                                AuthorizationGrantType.DEVICE_CODE, AuthorizationGrantType.REFRESH_TOKEN).contains(grant))) {
            throw OAuth2ClientRegistrationService.invalidMetadata(OAuth2ClientMetadataClaimNames.GRANT_TYPES);
        }
        if (request.grantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE) && request.redirectUris().isEmpty()) {
            throw OAuth2ClientRegistrationService.invalidMetadata(OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
        }
        for (String value : request.redirectUris()) {
            try {
                URI uri = new URI(value);
                String scheme = uri.getScheme();
                if (scheme != null && uri.getFragment() == null && !Set.of("javascript", "data", "vbscript")
                        .contains(scheme.toLowerCase(java.util.Locale.ROOT)))
                    continue;
            } catch (java.net.URISyntaxException ignored) {
                // Report the field, never reflect attacker input.
            }
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_redirect_uri", "Invalid redirect_uris", null));
        }
        for (String scope : request.scopes()) {
            if (scope.isEmpty() || !scope.chars().allMatch(c -> c == 0x21 || c >= 0x23 && c <= 0x5b || c >= 0x5d && c <= 0x7e)
                    || Set.of("client.create", "client.read").contains(scope)) {
                throw OAuth2ClientRegistrationService.invalidMetadata(OAuth2ClientMetadataClaimNames.SCOPE);
            }
        }
    }

    public static OAuth2AuthenticationException invalidMetadata(String field) {
        return new OAuth2AuthenticationException(
                new OAuth2Error("invalid_client_metadata", "Invalid Client Registration: " + field,
                        "https://www.rfc-editor.org/rfc/rfc7591.html#section-3.2.2"));
    }

    private String generateKey() {
        byte[] bytes = new byte[32];
        this.random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static Map<String, Object> response(RegisteredClient client) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put(OAuth2ClientMetadataClaimNames.CLIENT_ID, client.getClientId());
        response.put(OAuth2ClientMetadataClaimNames.CLIENT_ID_ISSUED_AT, client.getClientIdIssuedAt().getEpochSecond());
        response.put(OAuth2ClientMetadataClaimNames.CLIENT_NAME, client.getClientName());
        response.put(OAuth2ClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD,
                client.getClientAuthenticationMethods().iterator().next().getValue());
        response.put(OAuth2ClientMetadataClaimNames.GRANT_TYPES,
                client.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).sorted().toList());
        if (client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE))
            response.put(OAuth2ClientMetadataClaimNames.RESPONSE_TYPES, List.of("code"));
        if (!client.getRedirectUris().isEmpty())
            response.put(OAuth2ClientMetadataClaimNames.REDIRECT_URIS, client.getRedirectUris().stream().sorted().toList());
        if (!client.getScopes().isEmpty())
            response.put(OAuth2ClientMetadataClaimNames.SCOPE, String.join(" ", client.getScopes().stream().sorted().toList()));
        if (client.getClientSecret() != null) {
            response.put(OAuth2ClientMetadataClaimNames.CLIENT_SECRET, client.getClientSecret());
            response.put(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT, 0L);
        }
        return Map.copyOf(response);
    }
}
