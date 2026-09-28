package io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceConsentPolicy;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceVerificationContext;
import io.quarkus.arc.DefaultBean;

@Singleton
@DefaultBean
public final class DefaultDeviceConsentPolicy implements DeviceConsentPolicy {
    @Override
    public boolean isConsentRequired(DeviceVerificationContext context) {
        java.util.Set<String> scopes = context.authorization().getAttribute(OAuth2ParameterNames.SCOPE);
        return context.authorizationConsent() == null
                || !context.authorizationConsent().getScopes().containsAll(scopes);
    }
}
