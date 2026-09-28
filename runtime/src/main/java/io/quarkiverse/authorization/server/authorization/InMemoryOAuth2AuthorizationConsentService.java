package io.quarkiverse.authorization.server.authorization;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkus.arc.DefaultBean;

/**
 * In-memory authorization consent service intended for development and testing.
 */
@Singleton
@DefaultBean
public final class InMemoryOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private final Map<Integer, OAuth2AuthorizationConsent> authorizationConsents = new ConcurrentHashMap<>();

    public InMemoryOAuth2AuthorizationConsentService() {
        this(List.of());
    }

    public InMemoryOAuth2AuthorizationConsentService(OAuth2AuthorizationConsent... authorizationConsents) {
        this(Arrays.asList(authorizationConsents));
    }

    public InMemoryOAuth2AuthorizationConsentService(List<OAuth2AuthorizationConsent> authorizationConsents) {
        Objects.requireNonNull(authorizationConsents, "authorizationConsents cannot be null")
                .forEach(authorizationConsent -> {
                    Objects.requireNonNull(authorizationConsent, "authorizationConsent cannot be null");
                    int id = getId(authorizationConsent);
                    if (this.authorizationConsents.containsKey(id)) {
                        throw new IllegalArgumentException(
                                "The authorizationConsent must be unique. Found duplicate, with registered client id: ["
                                        + authorizationConsent.getRegisteredClientId() + "] and principal name: ["
                                        + authorizationConsent.getPrincipalName() + "]");
                    }
                    this.authorizationConsents.put(id, authorizationConsent);
                });
    }

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Objects.requireNonNull(authorizationConsent, "authorizationConsent cannot be null");
        this.authorizationConsents.put(getId(authorizationConsent), authorizationConsent);
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Objects.requireNonNull(authorizationConsent, "authorizationConsent cannot be null");
        this.authorizationConsents.remove(getId(authorizationConsent), authorizationConsent);
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Arguments.requireNonBlank(registeredClientId, "registeredClientId");
        Arguments.requireNonBlank(principalName, "principalName");
        return this.authorizationConsents.get(getId(registeredClientId, principalName));
    }

    private static int getId(String registeredClientId, String principalName) {
        return Objects.hash(registeredClientId, principalName);
    }

    private static int getId(OAuth2AuthorizationConsent authorizationConsent) {
        return getId(authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
    }
}
