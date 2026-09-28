package io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import jakarta.enterprise.inject.Default;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceAuthorizationConsentContext;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceConsentCustomizer;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceConsentSubmission;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkus.arc.All;
import io.quarkus.security.identity.SecurityIdentity;

/** Validates and persists a Device Authorization Consent. */
@Singleton
public final class DeviceConsentService {

    static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2AuthorizationConsentService authorizationConsentService;
    private final DeviceConsentCustomizer authorizationConsentCustomizer;

    @Inject
    public DeviceConsentService(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            OAuth2AuthorizationConsentService authorizationConsentService,
            @All @Default List<DeviceConsentCustomizer> authorizationConsentCustomizers) {
        var authorizationConsentCustomizersSnapshot = List.copyOf(authorizationConsentCustomizers);

        this.registeredClientRepository = Objects.requireNonNull(
                registeredClientRepository, "registeredClientRepository cannot be null");
        this.authorizationService = Objects.requireNonNull(authorizationService, "authorizationService cannot be null");
        this.authorizationConsentService = Objects.requireNonNull(
                authorizationConsentService, "authorizationConsentService cannot be null");
        this.authorizationConsentCustomizer = context -> authorizationConsentCustomizersSnapshot.forEach(
                policy -> policy.customize(context));
    }

    /** Executes synchronously. The endpoint supplies the worker and CDI request context. */
    public DeviceVerificationOutcome.Approved consent(DeviceConsentSubmission request) {
        Objects.requireNonNull(request, "request cannot be null");
        OAuth2Authorization authorization = this.authorizationService.findByToken(request.getState(), STATE_TOKEN_TYPE);
        if (authorization == null) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
        }

        SecurityIdentity principal = request.getPrincipal();
        if (principal.isAnonymous()
                || !principal.getPrincipal().getName().equals(authorization.getPrincipalName())) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
        }

        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(request.getClientId());
        if (registeredClient == null
                || !registeredClient.getId().equals(authorization.getRegisteredClientId())) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
        }

        OAuth2Authorization.Token<OAuth2DeviceCode> deviceCodeToken = authorization.getToken(OAuth2DeviceCode.class);
        OAuth2Authorization.Token<OAuth2UserCode> userCodeToken = authorization.getToken(OAuth2UserCode.class);
        if (deviceCodeToken == null
                || userCodeToken == null
                || !deviceCodeToken.isActive()
                || !userCodeToken.isActive()
                || !userCodeToken.getToken().getTokenValue().equals(request.getUserCode())) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
        }

        Set<String> requestedScopes = authorization.getAttribute(OAuth2ParameterNames.SCOPE);
        if (requestedScopes == null) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
        }
        if (!requestedScopes.containsAll(request.getScopes())) {
            throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE);
        }

        // Rejecting this device does not revoke consent previously granted to the client.
        if (!request.isApproved()) {
            deny(authorization);
        }

        // Reuse the scope decision shown on this confirmation page, including policy-approved scopes.
        Set<String> authorizedScopes = new HashSet<>(authorization.getAuthorizedScopes());
        authorizedScopes.addAll(request.getScopes());

        OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
                authorization.getRegisteredClientId(), principal.getPrincipal().getName());
        OAuth2AuthorizationConsent.Builder authorizationConsentBuilder = currentAuthorizationConsent != null
                ? OAuth2AuthorizationConsent.from(currentAuthorizationConsent)
                : OAuth2AuthorizationConsent.withId(
                        authorization.getRegisteredClientId(),
                        principal.getPrincipal().getName());
        authorizedScopes.forEach(authorizationConsentBuilder::scope);

        if (this.authorizationConsentCustomizer != null) {
            this.authorizationConsentCustomizer.customize(
                    new DeviceAuthorizationConsentContext(
                            request, authorizationConsentBuilder, registeredClient, authorization));
        }

        Set<String> authorities = new HashSet<>();
        authorizationConsentBuilder.authorities(authorities::addAll);
        if (authorities.isEmpty()) {
            if (!requestedScopes.isEmpty()) {
                deny(authorization);
            }
        } else {
            OAuth2AuthorizationConsent authorizationConsent = authorizationConsentBuilder.build();
            if (!authorizationConsent.equals(currentAuthorizationConsent)) {
                this.authorizationConsentService.save(authorizationConsent);
            }
        }

        OAuth2Authorization approvedAuthorization = OAuth2Authorization.from(authorization)
                .authorizedScopes(authorizedScopes)
                .invalidate(userCodeToken.getToken())
                .attributes(
                        attributes -> {
                            attributes.remove(OAuth2ParameterNames.STATE);
                            attributes.remove(OAuth2ParameterNames.SCOPE);
                        })
                .build();
        this.authorizationService.save(approvedAuthorization);

        return new DeviceVerificationOutcome.Approved(registeredClient.getClientId());
    }

    private void deny(OAuth2Authorization authorization) {
        OAuth2Authorization deniedAuthorization = OAuth2Authorization.from(authorization)
                .invalidate(authorization.getToken(OAuth2DeviceCode.class).getToken())
                .invalidate(authorization.getToken(OAuth2UserCode.class).getToken())
                .authorizedScopes(Set.of())
                .attributes(
                        attributes -> {
                            attributes.remove(OAuth2ParameterNames.STATE);
                            attributes.remove(OAuth2ParameterNames.SCOPE);
                        })
                .build();
        this.authorizationService.save(deniedAuthorization);
        throwError(OAuth2ErrorCodes.ACCESS_DENIED, OAuth2ParameterNames.CLIENT_ID);
    }

    private static void throwError(String errorCode, String parameterName) {
        throw new OAuth2AuthenticationException(
                new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI));
    }
}
