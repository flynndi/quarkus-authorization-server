package io.quarkiverse.authorization.server.runtime.oidc.registration;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.ClientSecretEncoder;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcClientMetadataClaimNames;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.registration.ClientRegistrationMapper;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationContext;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationRequest;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationRequestValidator;
import io.quarkiverse.authorization.server.oidc.registration.RegisteredClientMapper;
import io.quarkiverse.authorization.server.runtime.authentication.OAuth2AuthenticationProviderUtils;
import io.quarkiverse.authorization.server.runtime.client.registration.RegistrationAccessTokens;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

/**
 * Registers clients and issues registration access tokens; the HTTP adapter owns execution context.
 */
@Singleton
public final class OidcClientRegistrationService {

    static final String DEFAULT_CLIENT_REGISTRATION_AUTHORIZED_SCOPE = "client.create";

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final AuthorizationServerContext serverContext;
    private final AuthorizationServerKeyManager keyManager;
    private final RegisteredClientMapper registeredClientConverter;
    private final ClientRegistrationMapper clientRegistrationConverter;
    private final ClientSecretEncoder passwordEncoder;
    private final OidcClientRegistrationRequestValidator requestValidator;

    @Inject
    public OidcClientRegistrationService(
            RegisteredClientRepository repository,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            AuthorizationServerContext serverContext,
            AuthorizationServerKeyManager keyManager,
            OidcClientRegistrationRequestValidator requestValidator,
            RegisteredClientMapper registeredClientConverter,
            ClientRegistrationMapper clientRegistrationConverter,
            ClientSecretEncoder passwordEncoder) {

        this.registeredClientRepository = Objects.requireNonNull(repository);
        this.authorizationService = Objects.requireNonNull(authorizationService);
        this.tokenGenerator = Objects.requireNonNull(tokenGenerator);
        this.serverContext = Objects.requireNonNull(serverContext);
        this.keyManager = keyManager;
        this.requestValidator = Objects.requireNonNull(requestValidator, "validator cannot be null");
        this.registeredClientConverter = Objects.requireNonNull(
                registeredClientConverter, "registeredClientMapper cannot be null");
        this.clientRegistrationConverter = Objects.requireNonNull(
                clientRegistrationConverter, "clientRegistrationMapper cannot be null");
        this.passwordEncoder = Objects.requireNonNull(passwordEncoder, "secretEncoder cannot be null");
    }

    /** Executes synchronously. The endpoint supplies the worker and CDI request context. */
    public OidcClientRegistration register(OidcClientRegistrationRequest request) {
        Objects.requireNonNull(request, "request cannot be null");
        OAuth2Authorization initialAuthorization = RegistrationAccessTokens.getAccessTokenAuthorization(
                request.getPrincipal(),
                this.authorizationService,
                DEFAULT_CLIENT_REGISTRATION_AUTHORIZED_SCOPE);
        new OidcClientRegistrationMetadataValidator(this.keyManager.getSigningAlgorithms())
                .validateSupportedMetadata(request.getClientRegistration());
        this.requestValidator.validate(new OidcClientRegistrationContext(request));
        RegisteredClient client = Objects.requireNonNull(
                this.registeredClientConverter.map(request.getClientRegistration()));
        RegisteredClient storedClient = client;
        // HMAC requires the original shared key for client_secret_jwt; a bcrypt hash cannot replace it.
        if (client.getClientSecret() != null
                && !client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_JWT)) {
            String encodedSecret = this.passwordEncoder.encode(client.getClientSecret());
            if (encodedSecret == null
                    || encodedSecret.isBlank()
                    || encodedSecret.equals(client.getClientSecret())) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
            }
            storedClient = RegisteredClient.from(client).clientSecret(encodedSecret).build();
        }
        // Prepare every fallible conversion/token operation before the first storage write.
        OAuth2Authorization registrationAuthorization = generateAuthorization(storedClient, request);
        OidcClientRegistration.Builder response = OidcClientRegistration.withClaims(
                this.clientRegistrationConverter.map(client).getClaims())
                .registrationClientUrl(
                        OidcRegistrationSupport.registrationClientUrl(
                                this.serverContext, client.getClientId()))
                .registrationAccessToken(
                        registrationAuthorization
                                .getAccessToken()
                                .getToken()
                                .getTokenValue());
        // Credentials are issued here, not delegated to response metadata customizers.
        response.claims(
                claims -> {
                    claims.remove(OidcClientMetadataClaimNames.CLIENT_SECRET);
                    claims.remove(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT);
                });
        if (client.getClientSecret() != null) {
            response.clientSecret(client.getClientSecret())
                    .clientSecretExpiresAt(client.getClientSecretExpiresAt());
        }
        OidcClientRegistration result = response.build();
        // These repository writes do not share an automatic transaction or cross-instance compare-and-set.
        this.registeredClientRepository.save(storedClient);
        this.authorizationService.save(registrationAuthorization);
        this.authorizationService.save(RegistrationAccessTokens.invalidate(initialAuthorization));
        return result;
    }

    private OAuth2Authorization generateAuthorization(
            RegisteredClient client, OidcClientRegistrationRequest request) {
        Set<String> scopes = new HashSet<>();
        scopes.add(OidcClientConfigurationService.DEFAULT_CLIENT_CONFIGURATION_AUTHORIZED_SCOPE);
        scopes = Collections.unmodifiableSet(scopes);
        var clientPrincipal = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(client.getClientId()))
                .build();
        var tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal(clientPrincipal)
                .authorizationServerContext(
                        new DefaultAuthorizationServerContext(this.serverContext))
                .authorizedScopes(scopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(request)
                .build();
        // Registration access tokens use a client_credentials token context; this does not add that
        // grant to the registered client.
        OAuth2Token generated = this.tokenGenerator.generate(tokenContext);
        if (generated == null
                || generated instanceof OidcIdToken
                || generated instanceof OAuth2RefreshToken
                || generated instanceof OAuth2AuthorizationCode) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
        }
        OAuth2Authorization.Builder authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName(client.getClientId())
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(scopes);
        OAuth2AuthenticationProviderUtils.accessToken(authorization, generated, tokenContext);
        OAuth2Authorization result = authorization.build();
        if (!result.getAccessToken().isActive()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
        }
        return result;
    }
}
