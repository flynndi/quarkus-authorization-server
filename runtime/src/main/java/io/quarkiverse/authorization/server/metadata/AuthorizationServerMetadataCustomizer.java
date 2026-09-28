package io.quarkiverse.authorization.server.metadata;

/**
 * Customizes OAuth server metadata for each request. CDI beans are composed in ArC priority order;
 * changing advertised metadata does not install routes or enable protocol capabilities.
 */
@FunctionalInterface
public interface AuthorizationServerMetadataCustomizer {
    void customize(OAuth2AuthorizationServerMetadata.Builder metadata);
}
