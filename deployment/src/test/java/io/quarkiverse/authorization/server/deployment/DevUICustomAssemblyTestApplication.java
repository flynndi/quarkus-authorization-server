package io.quarkiverse.authorization.server.deployment;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.token.AuthorizationServerKeySource;

@Singleton
public class DevUICustomAssemblyTestApplication {
    private boolean started;

    void started(@jakarta.enterprise.event.Observes io.quarkus.runtime.StartupEvent event) {
        this.started = true;
    }

    @Produces
    @Singleton
    RegisteredClientRepository clients() {
        return new DevUIAssemblyTestSupport.UnqueriedClients();
    }

    @Produces
    @Singleton
    AuthorizationServerKeySource source() {
        if (this.started) {
            throw new IllegalStateException("Dev UI must not invoke a producer after startup");
        }
        return new DevUIAssemblyTestSupport.OnceKeySource("application-key");
    }
}
