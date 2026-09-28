package io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceConsentPolicy;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceVerificationContext;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceVerificationRequest;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

/** Prepares a device confirmation; scope consent alone never approves a new device. */
@Singleton
public final class DeviceVerificationService {

    static final OAuth2TokenType USER_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.USER_CODE);
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final SecureRandom STATE_RANDOM = new SecureRandom();

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2AuthorizationConsentService authorizationConsentService;
    private final DeviceConsentPolicy authorizationConsentRequired;

    @Inject
    public DeviceVerificationService(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            OAuth2AuthorizationConsentService authorizationConsentService,
            DeviceConsentPolicy authorizationConsentRequired) {

        this.registeredClientRepository = Objects.requireNonNull(
                registeredClientRepository, "registeredClientRepository cannot be null");
        this.authorizationService = Objects.requireNonNull(authorizationService, "authorizationService cannot be null");
        this.authorizationConsentService = Objects.requireNonNull(
                authorizationConsentService, "authorizationConsentService cannot be null");
        this.authorizationConsentRequired = Objects.requireNonNull(
                authorizationConsentRequired, "consentPolicy cannot be null");
    }

    /** Executes synchronously. The endpoint supplies the worker and CDI request context. */
    public DeviceVerificationOutcome.ConfirmationRequired verify(
            DeviceVerificationRequest request) {
        Objects.requireNonNull(request, "request cannot be null");
        OAuth2Authorization authorization = this.authorizationService.findByToken(request.getUserCode(), USER_CODE_TOKEN_TYPE);
        if (authorization == null) {
            throwError(OAuth2ErrorCodes.INVALID_GRANT, OAuth2ParameterNames.USER_CODE);
        }

        OAuth2Authorization.Token<OAuth2UserCode> userCode = authorization.getToken(OAuth2UserCode.class);
        if (userCode == null || !userCode.isActive()) {
            throwError(OAuth2ErrorCodes.INVALID_GRANT, OAuth2ParameterNames.USER_CODE);
        }

        SecurityIdentity principal = request.getPrincipal();
        if (principal.isAnonymous()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        }

        RegisteredClient registeredClient = this.registeredClientRepository.findById(authorization.getRegisteredClientId());
        if (registeredClient == null) {
            throwError(OAuth2ErrorCodes.INVALID_GRANT, OAuth2ParameterNames.USER_CODE);
        }

        Set<String> requestedScopes = authorization.getAttribute(OAuth2ParameterNames.SCOPE);
        if (requestedScopes == null) {
            throwError(OAuth2ErrorCodes.INVALID_GRANT, OAuth2ParameterNames.USER_CODE);
        }
        OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
                registeredClient.getId(), principal.getPrincipal().getName());

        DeviceVerificationContext consentContext = new DeviceVerificationContext(
                request, registeredClient, authorization, currentAuthorizationConsent);
        Set<String> approvedScopes = new HashSet<>(requestedScopes);
        if (this.authorizationConsentRequired.isConsentRequired(consentContext)) {
            approvedScopes.retainAll(
                    currentAuthorizationConsent != null
                            ? currentAuthorizationConsent.getScopes()
                            : Collections.emptySet());
        }
        // These scopes need no new consent, but the active user code keeps polling pending until
        // the user explicitly confirms this device. State binds that confirmation to this request.
        String state = generateState();
        OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
                .principalName(principal.getPrincipal().getName())
                .authorizedScopes(approvedScopes)
                .attribute(
                        SecurityIdentity.class.getName(),
                        QuarkusSecurityIdentity.builder()
                                .setPrincipal(
                                        new QuarkusPrincipal(
                                                principal.getPrincipal().getName()))
                                .addRoles(principal.getRoles())
                                .build())
                .attribute(OAuth2ParameterNames.STATE, state)
                .build();
        this.authorizationService.save(updatedAuthorization);

        return new DeviceVerificationOutcome.ConfirmationRequired(
                registeredClient.getClientId(),
                principal,
                requestedScopes,
                approvedScopes,
                request.getUserCode(),
                state);
    }

    private static String generateState() {
        byte[] bytes = new byte[32];
        STATE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().encodeToString(bytes);
    }

    private static void throwError(String errorCode, String parameterName) {
        throw new OAuth2AuthenticationException(
                new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI));
    }
}
