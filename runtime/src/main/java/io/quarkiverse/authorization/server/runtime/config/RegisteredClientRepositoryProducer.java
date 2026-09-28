package io.quarkiverse.authorization.server.runtime.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.InMemoryRegisteredClientRepository;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jose.jws.JwsAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.runtime.client.authentication.ClientJwkSetCache;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkus.arc.DefaultBean;

/** Produces the default in-memory client repository from Quarkus configuration. */
@Singleton
public final class RegisteredClientRepositoryProducer {

    @Produces
    @Singleton
    @DefaultBean
    RegisteredClientRepository registeredClientRepository(AuthorizationServerRuntimeConfig config) {
        List<RegisteredClient> registeredClients = new ArrayList<>();
        config.clients()
                .forEach(
                        (clientId, clientConfig) -> {
                            RegisteredClient.Builder builder = RegisteredClient.withId(clientConfig.id().orElse(clientId))
                                    .clientId(clientId);
                            clientConfig.clientName().ifPresent(builder::clientName);
                            clientConfig.clientSecret().ifPresent(builder::clientSecret);
                            clientConfig.clientIdIssuedAt().ifPresent(builder::clientIdIssuedAt);
                            clientConfig
                                    .clientSecretExpiresAt()
                                    .ifPresent(builder::clientSecretExpiresAt);
                            clientConfig.clientAuthenticationMethods().stream()
                                    .map(ClientAuthenticationMethod::new)
                                    .forEach(builder::clientAuthenticationMethod);
                            clientConfig.authorizationGrantTypes().stream()
                                    .map(AuthorizationGrantType::new)
                                    .forEach(builder::authorizationGrantType);
                            clientConfig
                                    .redirectUris()
                                    .orElseGet(Set::of)
                                    .forEach(builder::redirectUri);
                            clientConfig
                                    .postLogoutRedirectUris()
                                    .orElseGet(Set::of)
                                    .forEach(builder::postLogoutRedirectUri);
                            clientConfig.scopes().orElseGet(Set::of).forEach(builder::scope);
                            // Preserve RegisteredClient's inferred public-client defaults when a
                            // value is omitted.
                            var clientSettings = ClientSettings.withSettings(
                                    builder.build().getClientSettings().getSettings());
                            clientConfig
                                    .requireProofKey()
                                    .ifPresent(clientSettings::requireProofKey);
                            clientConfig
                                    .requireAuthorizationConsent()
                                    .ifPresent(clientSettings::requireAuthorizationConsent);
                            clientConfig.jwkSetUrl().ifPresent(location -> {
                                ClientJwkSetCache.validateJwkSetUrl(location);
                                clientSettings.jwkSetUrl(location);
                            });
                            clientConfig.tokenEndpointAuthenticationSigningAlgorithm().ifPresent(name -> {
                                JwsAlgorithm algorithm = JwsAlgorithm.from(name);
                                if (algorithm == null) {
                                    throw new IllegalArgumentException(
                                            "Unsupported client assertion signing algorithm: " + name);
                                }
                                clientSettings.tokenEndpointAuthenticationSigningAlgorithm(algorithm);
                            });
                            clientConfig.x509CertificateSubjectDn().ifPresent(dn -> {
                                new X500Principal(
                                        Arguments.requireNonBlank(dn, "x509CertificateSubjectDn"));
                                clientSettings.x509CertificateSubjectDN(dn);
                            });
                            builder.clientSettings(clientSettings.build());
                            TokenSettings.Builder tokenSettings = TokenSettings.builder();
                            clientConfig
                                    .authorizationCodeTimeToLive()
                                    .ifPresent(tokenSettings::authorizationCodeTimeToLive);
                            clientConfig
                                    .accessTokenTimeToLive()
                                    .ifPresent(tokenSettings::accessTokenTimeToLive);
                            clientConfig
                                    .accessTokenFormat()
                                    .ifPresent(tokenSettings::accessTokenFormat);
                            clientConfig
                                    .deviceCodeTimeToLive()
                                    .ifPresent(tokenSettings::deviceCodeTimeToLive);
                            clientConfig
                                    .refreshTokenTimeToLive()
                                    .ifPresent(tokenSettings::refreshTokenTimeToLive);
                            clientConfig
                                    .reuseRefreshTokens()
                                    .ifPresent(tokenSettings::reuseRefreshTokens);
                            clientConfig
                                    .idTokenSignatureAlgorithm()
                                    .ifPresent(tokenSettings::idTokenSignatureAlgorithm);
                            builder.tokenSettings(tokenSettings.build());
                            registeredClients.add(builder.build());
                        });
        return new InMemoryRegisteredClientRepository(registeredClients);
    }
}
