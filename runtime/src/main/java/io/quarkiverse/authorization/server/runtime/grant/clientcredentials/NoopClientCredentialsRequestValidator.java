package io.quarkiverse.authorization.server.runtime.grant.clientcredentials;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequestContext;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequestValidator;
import io.quarkus.arc.DefaultBean;

@Singleton
@DefaultBean
public final class NoopClientCredentialsRequestValidator
        implements ClientCredentialsRequestValidator {
    @Override
    public void validate(ClientCredentialsRequestContext context) {
    }
}
