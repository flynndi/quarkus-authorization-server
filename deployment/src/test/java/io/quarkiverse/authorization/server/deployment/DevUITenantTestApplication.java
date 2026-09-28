package io.quarkiverse.authorization.server.deployment;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.tenant.AuthorizationServerTenant;
import io.smallrye.common.annotation.Identifier;

@Singleton
public class DevUITenantTestApplication {
    @Produces
    @Singleton
    @Identifier("alpha")
    AuthorizationServerTenant alpha() {
        return DevUITenantTestApplication.tenant("alpha");
    }

    @Produces
    @Singleton
    @Identifier("beta")
    AuthorizationServerTenant beta() {
        return DevUITenantTestApplication.tenant("beta");
    }

    private static AuthorizationServerTenant tenant(String id) {
        return new AuthorizationServerTenant(new DevUIAssemblyTestSupport.UnqueriedClients(),
                new InMemoryOAuth2AuthorizationService(),
                new InMemoryOAuth2AuthorizationConsentService(), new DevUIAssemblyTestSupport.OnceKeySource(id));
    }
}
