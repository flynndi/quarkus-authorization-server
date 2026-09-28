package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import jakarta.enterprise.inject.Default;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeGenerator;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentContext;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentCustomizer;
import io.quarkiverse.authorization.server.grant.authorizationcode.ConsentSubmission;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcScopes;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.arc.All;
import io.quarkus.security.identity.SecurityIdentity;

/** Validates and persists an OAuth 2.0 Authorization Consent. */
@Singleton
public final class AuthorizationConsentProcessor {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
    private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2AuthorizationConsentService authorizationConsentService;
    private final AuthorizationServerContext authorizationServerContext;
    private final AuthorizationCodeGenerator authorizationCodeGenerator;
    private final AuthorizationConsentCustomizer authorizationConsentCustomizer;

    @Inject
    public AuthorizationConsentProcessor(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            OAuth2AuthorizationConsentService authorizationConsentService,
            AuthorizationServerContext authorizationServerContext,
            AuthorizationCodeGenerator authorizationCodeGenerator,
            @All @Default List<AuthorizationConsentCustomizer> authorizationConsentCustomizers) {
        var authorizationConsentCustomizersSnapshot = List.copyOf(authorizationConsentCustomizers);

        this.registeredClientRepository = Objects.requireNonNull(
                registeredClientRepository, "registeredClientRepository cannot be null");
        this.authorizationService = Objects.requireNonNull(authorizationService, "authorizationService cannot be null");
        this.authorizationConsentService = Objects.requireNonNull(
                authorizationConsentService, "authorizationConsentService cannot be null");
        this.authorizationServerContext = Objects.requireNonNull(
                authorizationServerContext, "authorizationServerContext cannot be null");
        this.authorizationCodeGenerator = Objects.requireNonNull(authorizationCodeGenerator, "codeGenerator cannot be null");
        this.authorizationConsentCustomizer = context -> authorizationConsentCustomizersSnapshot.forEach(
                policy -> policy.customize(context));
    }

    /** Executes synchronously. The endpoint supplies the worker and CDI request context. */
    public AuthorizationOutcome.CodeIssued consent(ConsentSubmission authentication) {
        Objects.requireNonNull(authentication, "authentication cannot be null");
        OAuth2Authorization authorization = this.authorizationService.findByToken(authentication.getState(), STATE_TOKEN_TYPE);
        if (authorization == null) {
            throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.STATE,
                    authentication,
                    null,
                    null);
        }

        SecurityIdentity principal = authentication.getPrincipal();
        if (principal.isAnonymous()
                || !principal.getPrincipal().getName().equals(authorization.getPrincipalName())) {
            throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.STATE,
                    authentication,
                    null,
                    null);
        }

        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(authentication.getClientId());
        if (registeredClient == null
                || !registeredClient.getId().equals(authorization.getRegisteredClientId())) {
            throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.CLIENT_ID,
                    authentication,
                    registeredClient,
                    null);
        }

        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        if (authorizationRequest == null) {
            throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.STATE,
                    authentication,
                    null,
                    null);
        }

        Set<String> requestedScopes = authorizationRequest.getScopes();
        Set<String> authorizedScopes = new HashSet<>(authentication.getScopes());
        if (!requestedScopes.containsAll(authorizedScopes)) {
            throwError(
                    OAuth2ErrorCodes.INVALID_SCOPE,
                    OAuth2ParameterNames.SCOPE,
                    authentication,
                    registeredClient,
                    authorizationRequest);
        }

        OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
                authorization.getRegisteredClientId(), authorization.getPrincipalName());
        Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null
                ? currentAuthorizationConsent.getScopes()
                : Collections.emptySet();
        for (String requestedScope : requestedScopes) {
            if (currentAuthorizedScopes.contains(requestedScope)) {
                authorizedScopes.add(requestedScope);
            }
        }

        if (!authorizedScopes.isEmpty() && requestedScopes.contains(OidcScopes.OPENID)) {
            // 'openid' is auto-approved only after consent to another requested scope.
            authorizedScopes.add(OidcScopes.OPENID);
        }

        OAuth2AuthorizationConsent.Builder authorizationConsentBuilder = currentAuthorizationConsent != null
                ? OAuth2AuthorizationConsent.from(currentAuthorizationConsent)
                : OAuth2AuthorizationConsent.withId(
                        authorization.getRegisteredClientId(),
                        authorization.getPrincipalName());
        authorizedScopes.forEach(authorizationConsentBuilder::scope);

        AuthorizationConsentContext consentContext = AuthorizationConsentContext.with(authentication)
                .authorizationConsent(authorizationConsentBuilder)
                .registeredClient(registeredClient)
                .authorization(authorization)
                .authorizationRequest(authorizationRequest)
                .build();
        this.authorizationConsentCustomizer.customize(consentContext);

        Set<String> authorities = new HashSet<>();
        authorizationConsentBuilder.authorities(authorities::addAll);
        if (authorities.isEmpty() || consentContext.getDecision() == AuthorizationConsentContext.Decision.DENY) {
            // Empty authorities revoke the stored consent. Otherwise a denial only
            // cancels this request; candidate consent changes are not persisted on denial.
            if (authorities.isEmpty() && currentAuthorizationConsent != null) {
                this.authorizationConsentService.remove(currentAuthorizationConsent);
            }
            this.authorizationService.remove(authorization);
            AuthorizationConsentProcessor.throwError(
                    OAuth2ErrorCodes.ACCESS_DENIED,
                    OAuth2ParameterNames.CLIENT_ID,
                    authentication,
                    registeredClient,
                    authorizationRequest);
        }

        OAuth2AuthorizationConsent authorizationConsent = authorizationConsentBuilder.build();
        // Use the customized scopes for both the code and persisted authorization, while
        // leaving unrelated historical consent out of this request's authorization.
        authorizedScopes = new HashSet<>(authorizationConsent.getScopes());
        authorizedScopes.retainAll(requestedScopes);
        if (!authorizationConsent.equals(currentAuthorizationConsent)) {
            this.authorizationConsentService.save(authorizationConsent);
        }

        OAuth2TokenContext tokenContext = createAuthorizationCodeTokenContext(
                authentication, registeredClient, authorization, authorizedScopes);
        OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
        if (authorizationCode == null) {
            OAuth2Error error = new OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the authorization code.",
                    ERROR_URI);
            throw new AuthorizationRequestException(error, null);
        }

        OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
                .authorizedScopes(authorizedScopes)
                .token(authorizationCode)
                .attributes(
                        attributes -> {
                            attributes.remove(OAuth2ParameterNames.STATE);
                            // Consent can complete after reauthentication; bind the session
                            // that actually approves it.
                            attributes.remove(SessionInformation.class.getName());
                            SessionInformation session = authentication
                                    .getPrincipal()
                                    .getAttribute(
                                            SessionInformation.class.getName());
                            if (session != null
                                    && authorizationRequest
                                            .getScopes()
                                            .contains(OidcScopes.OPENID)) {
                                attributes.put(SessionInformation.class.getName(), session);
                            }
                        })
                .build();
        this.authorizationService.save(updatedAuthorization);

        String redirectUri = Arguments.hasText(authorizationRequest.getRedirectUri())
                ? authorizationRequest.getRedirectUri()
                : registeredClient.getRedirectUris().iterator().next();
        return new AuthorizationOutcome.CodeIssued(
                authorizationCode, redirectUri, authorizationRequest.getState(), authorizedScopes);
    }

    private OAuth2TokenContext createAuthorizationCodeTokenContext(
            ConsentSubmission authentication,
            RegisteredClient registeredClient,
            OAuth2Authorization authorization,
            Set<String> authorizedScopes) {
        return DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication.getPrincipal())
                .authorizationServerContext(
                        new DefaultAuthorizationServerContext(this.authorizationServerContext))
                .authorization(authorization)
                .tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authentication)
                .build();
    }

    private static void throwError(
            String errorCode,
            String parameterName,
            ConsentSubmission authentication,
            RegisteredClient registeredClient,
            OAuth2AuthorizationRequest authorizationRequest) {
        String redirectUri = resolveRedirectUri(authorizationRequest, registeredClient);
        if (OAuth2ErrorCodes.INVALID_REQUEST.equals(errorCode)
                && (OAuth2ParameterNames.CLIENT_ID.equals(parameterName)
                        || OAuth2ParameterNames.STATE.equals(parameterName))) {
            redirectUri = null;
        }

        String state = authorizationRequest != null
                ? authorizationRequest.getState()
                : authentication.getState();
        throw new AuthorizationRequestException(
                new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI),
                redirectUri == null ? null : new AuthorizationRedirect(redirectUri, state));
    }

    private static String resolveRedirectUri(
            OAuth2AuthorizationRequest authorizationRequest, RegisteredClient registeredClient) {
        if (authorizationRequest != null && Arguments.hasText(authorizationRequest.getRedirectUri())) {
            return authorizationRequest.getRedirectUri();
        }
        if (registeredClient != null && !registeredClient.getRedirectUris().isEmpty()) {
            return registeredClient.getRedirectUris().iterator().next();
        }
        return null;
    }
}
