package io.quarkiverse.authorization.server.runtime.oidc.registration;

import java.util.Objects;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcClientMetadataClaimNames;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.oidc.registration.ClientRegistrationMapper;
import io.quarkiverse.authorization.server.runtime.client.registration.RegistrationAccessTokens;

/** Reads the registration bound to the exact persisted registration access token. */
@Singleton
public final class OidcClientConfigurationService {

    static final String DEFAULT_CLIENT_CONFIGURATION_AUTHORIZED_SCOPE = "client.read";

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final AuthorizationServerContext serverContext;
    private final ClientRegistrationMapper clientRegistrationConverter;

    @Inject
    public OidcClientConfigurationService(
            RegisteredClientRepository repository,
            OAuth2AuthorizationService authorizationService,
            AuthorizationServerContext serverContext,
            ClientRegistrationMapper clientRegistrationConverter) {

        this.registeredClientRepository = Objects.requireNonNull(repository);
        this.authorizationService = Objects.requireNonNull(authorizationService);
        this.serverContext = Objects.requireNonNull(serverContext);
        this.clientRegistrationConverter = Objects.requireNonNull(
                clientRegistrationConverter, "clientRegistrationMapper cannot be null");
    }

    /** Executes synchronously. The endpoint supplies the worker and CDI request context. */
    public OidcClientRegistration read(OidcClientConfigurationRequest request) {
        Objects.requireNonNull(request, "request cannot be null");
        OAuth2Authorization authorization = RegistrationAccessTokens.getAccessTokenAuthorization(
                request.getPrincipal(),
                this.authorizationService,
                DEFAULT_CLIENT_CONFIGURATION_AUTHORIZED_SCOPE);
        RegisteredClient client = this.registeredClientRepository.findByClientId(request.getClientId());
        if (client == null || !client.getId().equals(authorization.getRegisteredClientId())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        // Never expose the stored hash to a converter or a configuration-read response.
        RegisteredClient publicMetadata = RegisteredClient.from(client)
                .clientSecret(null)
                .clientSecretExpiresAt(null)
                .build();
        OidcClientRegistration result = OidcClientRegistration.withClaims(
                this.clientRegistrationConverter.map(publicMetadata).getClaims())
                .registrationClientUrl(
                        OidcRegistrationSupport.registrationClientUrl(
                                this.serverContext, client.getClientId()))
                .claims(
                        claims -> {
                            claims.remove(OidcClientMetadataClaimNames.CLIENT_SECRET);
                            claims.remove(
                                    OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT);
                            claims.remove(
                                    OidcClientMetadataClaimNames.REGISTRATION_ACCESS_TOKEN);
                        })
                .build();
        return result;
    }
}
