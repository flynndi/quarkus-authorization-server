package io.quarkiverse.authorization.server.runtime.oidc;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.oidc.OidcProviderConfiguration;
import io.quarkiverse.authorization.server.oidc.OidcProviderMetadataCustomizer;
import io.quarkus.arc.DefaultBean;

@Singleton
@DefaultBean
public final class NoopOidcProviderMetadataCustomizer implements OidcProviderMetadataCustomizer {
    @Override
    public void customize(OidcProviderConfiguration.Builder metadata) {
    }
}
