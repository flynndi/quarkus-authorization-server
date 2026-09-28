package io.quarkiverse.authorization.server.runtime.tenant;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;

/** CDI adapters keep grant implementations independent of tenant lookup and storage technology. */
@Singleton
public final class TenantComponentProducer {

    @Produces
    @Singleton
    RegisteredClientRepository clients(AuthorizationServerTenantRegistry registry) {
        return new RegisteredClientRepository() {
            @Override
            public void save(RegisteredClient client) {
                registry.current().clients().save(client);
            }

            @Override
            public RegisteredClient findById(String id) {
                return registry.current().clients().findById(id);
            }

            @Override
            public RegisteredClient findByClientId(String id) {
                return registry.current().clients().findByClientId(id);
            }
        };
    }

    @Produces
    @Singleton
    OAuth2AuthorizationService authorizations(AuthorizationServerTenantRegistry registry) {
        return new OAuth2AuthorizationService() {
            @Override
            public void save(OAuth2Authorization authorization) {
                registry.current().authorizations().save(authorization);
            }

            @Override
            public void remove(OAuth2Authorization authorization) {
                registry.current().authorizations().remove(authorization);
            }

            @Override
            public OAuth2Authorization findById(String id) {
                return registry.current().authorizations().findById(id);
            }

            @Override
            public OAuth2Authorization findByToken(String value, OAuth2TokenType type) {
                return registry.current().authorizations().findByToken(value, type);
            }
        };
    }

    @Produces
    @Singleton
    OAuth2AuthorizationConsentService consents(AuthorizationServerTenantRegistry registry) {
        return new OAuth2AuthorizationConsentService() {
            @Override
            public void save(OAuth2AuthorizationConsent consent) {
                registry.current().consents().save(consent);
            }

            @Override
            public void remove(OAuth2AuthorizationConsent consent) {
                registry.current().consents().remove(consent);
            }

            @Override
            public OAuth2AuthorizationConsent findById(String client, String principal) {
                return registry.current().consents().findById(client, principal);
            }
        };
    }

    @Produces
    @Singleton
    AuthorizationServerKeyManager keys(AuthorizationServerTenantRegistry registry) {
        return AuthorizationServerKeyManager.delegating(registry::currentKeys);
    }
}
