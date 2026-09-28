package io.quarkiverse.authorization.server.oidc;

/**
 * Customizes OIDC discovery for each request in ArC priority order. This SPI is consumed only when
 * OIDC is enabled and does not change the build-time feature configuration.
 */
@FunctionalInterface
public interface OidcProviderMetadataCustomizer {
    void customize(OidcProviderConfiguration.Builder metadata);
}
