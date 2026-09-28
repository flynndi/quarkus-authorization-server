package io.quarkiverse.authorization.server.runtime.metadata;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.metadata.AuthorizationServerMetadataCustomizer;
import io.quarkiverse.authorization.server.metadata.OAuth2AuthorizationServerMetadata;
import io.quarkus.arc.DefaultBean;

@Singleton
@DefaultBean
public final class NoopAuthorizationServerMetadataCustomizer
        implements AuthorizationServerMetadataCustomizer {
    @Override
    public void customize(OAuth2AuthorizationServerMetadata.Builder metadata) {
    }
}
