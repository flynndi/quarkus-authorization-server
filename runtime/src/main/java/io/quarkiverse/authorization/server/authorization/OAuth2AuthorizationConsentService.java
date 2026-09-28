package io.quarkiverse.authorization.server.authorization;

/**
 * Manages OAuth 2.0 authorization consents.
 */
public interface OAuth2AuthorizationConsentService {

    void save(OAuth2AuthorizationConsent authorizationConsent);

    void remove(OAuth2AuthorizationConsent authorizationConsent);

    OAuth2AuthorizationConsent findById(String registeredClientId, String principalName);
}
