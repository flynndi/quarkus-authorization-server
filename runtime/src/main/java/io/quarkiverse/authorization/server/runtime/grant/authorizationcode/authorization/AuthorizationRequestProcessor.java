package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import java.security.SecureRandom;
import java.util.Base64;
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
import io.quarkiverse.authorization.server.endpoint.PkceParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeGenerator;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentPolicy;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequest;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestContext;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestValidator;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcScopes;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcErrorCodes;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcParameterNames;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcPrompt;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkiverse.authorization.server.runtime.authentication.OAuth2AuthenticationProviderUtils;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.arc.All;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

/** Validates an OAuth 2.0 Authorization Request used in the Authorization Code Grant. */
@Singleton
public final class AuthorizationRequestProcessor {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
    private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";
    private static final AuthorizationRequestChecks PROTOCOL_CHECKS = new AuthorizationRequestChecks();
    private static final SecureRandom STATE_RANDOM = new SecureRandom();

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2AuthorizationConsentService authorizationConsentService;
    private final AuthorizationServerContext authorizationServerContext;
    private final AuthorizationServerOidcConfig oidcConfig;
    private final AuthorizationCodeGenerator authorizationCodeGenerator;
    private final AuthorizationRequestValidator requestValidator;
    private final AuthorizationConsentPolicy consentPolicy;
    private final PushedAuthorizationRequests pushedRequests;

    @Inject
    public AuthorizationRequestProcessor(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            OAuth2AuthorizationConsentService authorizationConsentService,
            AuthorizationServerContext authorizationServerContext,
            AuthorizationServerOidcConfig oidcConfig,
            @All @Default List<AuthorizationRequestValidator> requestValidators,
            AuthorizationConsentPolicy consentPolicy,
            AuthorizationCodeGenerator authorizationCodeGenerator) {
        var requestValidatorsSnapshot = List.copyOf(requestValidators);

        this.registeredClientRepository = Objects.requireNonNull(
                registeredClientRepository, "registeredClientRepository cannot be null");
        this.authorizationService = Objects.requireNonNull(authorizationService, "authorizationService cannot be null");
        this.pushedRequests = new PushedAuthorizationRequests(this.authorizationService);
        this.authorizationConsentService = Objects.requireNonNull(
                authorizationConsentService, "authorizationConsentService cannot be null");
        this.authorizationServerContext = Objects.requireNonNull(
                authorizationServerContext, "authorizationServerContext cannot be null");
        this.oidcConfig = Objects.requireNonNull(oidcConfig, "oidcConfig cannot be null");
        this.requestValidator = context -> requestValidatorsSnapshot.forEach(policy -> policy.validate(context));
        this.consentPolicy = Objects.requireNonNull(consentPolicy, "consentPolicy cannot be null");
        this.authorizationCodeGenerator = Objects.requireNonNull(authorizationCodeGenerator, "codeGenerator cannot be null");
    }

    /** Client-to-server validation only: pushing a request never authenticates the resource owner. */
    public PushedAuthorizationResponse push(AuthorizationRequest request) {
        if (this.authorizationServerContext.getAuthorizationServerSettings().getPushedAuthorizationRequestEndpoint() == null
                || request.getAdditionalParameters().containsKey(OAuth2ParameterNames.REQUEST_URI)
                || request.getAdditionalParameters().containsKey("request")) {
            throw PushedAuthorizationRequests.invalidReference();
        }
        SecurityIdentity clientIdentity = OAuth2AuthenticationProviderUtils
                .getIdentifiedClientElseThrowInvalidClient(request.getPrincipal());
        RegisteredClient client = clientIdentity.getAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE);
        if (!client.getClientId().equals(request.getClientId())) {
            throw PushedAuthorizationRequests.invalidReference();
        }
        this.validate(request, client);
        return this.pushedRequests.save(request, client);
    }

    private void validate(AuthorizationRequest authentication, RegisteredClient registeredClient) {
        AuthorizationRequestContext authenticationContext = AuthorizationRequestContext.with(authentication)
                .registeredClient(registeredClient)
                .build();
        PROTOCOL_CHECKS.validate(authenticationContext);

        if (!registeredClient
                .getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            throwError(
                    OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
                    OAuth2ParameterNames.CLIENT_ID,
                    authentication,
                    registeredClient);
        }

        String codeChallenge = (String) authentication
                .getAdditionalParameters()
                .get(PkceParameterNames.CODE_CHALLENGE);
        if (Arguments.hasText(codeChallenge)) {
            String codeChallengeMethod = (String) authentication
                    .getAdditionalParameters()
                    .get(PkceParameterNames.CODE_CHALLENGE_METHOD);
            if (!"S256".equals(codeChallengeMethod)) {
                throwError(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        PkceParameterNames.CODE_CHALLENGE_METHOD,
                        PKCE_ERROR_URI,
                        authentication,
                        registeredClient);
            }
        } else if (registeredClient.getClientSettings().isRequireProofKey()) {
            throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    PkceParameterNames.CODE_CHALLENGE,
                    PKCE_ERROR_URI,
                    authentication,
                    registeredClient);
        }

        if (!this.oidcConfig.enabled() && authentication.getScopes().contains(OidcScopes.OPENID)) {
            throwError(
                    OAuth2ErrorCodes.INVALID_SCOPE,
                    OAuth2ParameterNames.SCOPE,
                    authentication,
                    registeredClient);
        }

        this.requestValidator.validate(authenticationContext);

    }

    /** Executes synchronously. The endpoint supplies the worker and CDI request context. */
    public AuthorizationOutcome authorize(AuthorizationRequest authentication) {
        Objects.requireNonNull(authentication, "authentication cannot be null");
        PushedAuthorizationRequests.Resolved pushed = null;
        if (authentication.getAdditionalParameters().containsKey(OAuth2ParameterNames.REQUEST_URI)) {
            if (this.authorizationServerContext.getAuthorizationServerSettings()
                    .getPushedAuthorizationRequestEndpoint() == null) {
                throw PushedAuthorizationRequests.invalidReference();
            }
            pushed = this.pushedRequests.resolve(authentication);
            authentication = pushed.request();
        }
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(authentication.getClientId());
        if (registeredClient == null) {
            throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.CLIENT_ID,
                    authentication,
                    null);
        }

        if (pushed != null && !pushed.authorization().getRegisteredClientId().equals(registeredClient.getId())) {
            throw PushedAuthorizationRequests.invalidReference();
        }
        this.validate(authentication, registeredClient);

        boolean silent = authentication.getPromptValues().contains(OidcPrompt.NONE);
        SecurityIdentity principal = authentication.getPrincipal();
        if (principal.isAnonymous()) {
            if (silent) {
                AuthorizationRequestProcessor.throwError(OidcErrorCodes.LOGIN_REQUIRED, OidcParameterNames.PROMPT,
                        authentication, registeredClient);
            }
            return new AuthorizationOutcome.LoginRequired();
        }

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(authentication.getAuthorizationUri())
                .clientId(registeredClient.getClientId())
                .redirectUri(authentication.getRedirectUri())
                .scopes(authentication.getScopes())
                .state(authentication.getState())
                .additionalParameters(authentication.getAdditionalParameters())
                .build();
        OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
                registeredClient.getId(), principal.getPrincipal().getName());

        // Request validation has completed; the predicate also receives prior consent.
        AuthorizationRequestContext consentContext = AuthorizationRequestContext.with(authentication)
                .registeredClient(registeredClient)
                .authorizationRequest(authorizationRequest)
                .authorizationConsent(currentAuthorizationConsent)
                .build();
        if (this.consentPolicy.isConsentRequired(consentContext)) {
            if (silent) {
                // Do not create pending consent state or display UI for prompt=none.
                AuthorizationRequestProcessor.throwError(OidcErrorCodes.CONSENT_REQUIRED, OidcParameterNames.PROMPT,
                        authentication, registeredClient);
            }
            String state = generateState();
            OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
                    .attribute(OAuth2ParameterNames.STATE, state)
                    .build();
            this.authorizationService.save(authorization);
            this.pushedRequests.consume(pushed);

            Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null
                    ? currentAuthorizationConsent.getScopes()
                    : null;
            return new AuthorizationOutcome.ConsentRequired(
                    authorizationRequest.getAuthorizationUri(),
                    registeredClient.getClientId(),
                    principal,
                    state,
                    authentication.getScopes(),
                    currentAuthorizedScopes);
        }

        OAuth2TokenContext tokenContext = createAuthorizationCodeTokenContext(
                authentication, registeredClient, null, authorizationRequest.getScopes());
        OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
        if (authorizationCode == null) {
            OAuth2Error error = new OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the authorization code.",
                    ERROR_URI);
            throw new AuthorizationRequestException(error, null);
        }

        OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
                .authorizedScopes(authorizationRequest.getScopes())
                .token(authorizationCode)
                .build();
        this.authorizationService.save(authorization);
        this.pushedRequests.consume(pushed);

        String redirectUri = Arguments.hasText(authentication.getRedirectUri())
                ? authentication.getRedirectUri()
                : registeredClient.getRedirectUris().iterator().next();
        return new AuthorizationOutcome.CodeIssued(
                authorizationCode,
                redirectUri,
                authentication.getState(),
                authentication.getScopes());
    }

    private static OAuth2Authorization.Builder authorizationBuilder(
            RegisteredClient registeredClient,
            SecurityIdentity principal,
            OAuth2AuthorizationRequest authorizationRequest) {
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(principal.getPrincipal().getName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(
                        SecurityIdentity.class.getName(),
                        QuarkusSecurityIdentity.builder()
                                .setPrincipal(
                                        new QuarkusPrincipal(
                                                principal.getPrincipal().getName()))
                                .addRoles(principal.getRoles())
                                .build())
                .attribute(
                        OAuth2AuthorizationRequest.class.getName(), authorizationRequest);
        SessionInformation session = principal.getAttribute(SessionInformation.class.getName());
        if (session != null && authorizationRequest.getScopes().contains(OidcScopes.OPENID)) {
            builder.attribute(SessionInformation.class.getName(), session);
        }
        return builder;
    }

    private OAuth2TokenContext createAuthorizationCodeTokenContext(
            AuthorizationRequest authentication,
            RegisteredClient registeredClient,
            OAuth2Authorization authorization,
            Set<String> authorizedScopes) {
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication.getPrincipal())
                .authorizationServerContext(
                        new DefaultAuthorizationServerContext(
                                this.authorizationServerContext))
                .tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authentication);
        if (authorization != null) {
            tokenContextBuilder.authorization(authorization);
        }
        return tokenContextBuilder.build();
    }

    private static String generateState() {
        byte[] bytes = new byte[32];
        STATE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static void throwError(
            String errorCode,
            String parameterName,
            AuthorizationRequest authentication,
            RegisteredClient registeredClient) {
        throwError(errorCode, parameterName, ERROR_URI, authentication, registeredClient);
    }

    private static void throwError(
            String errorCode,
            String parameterName,
            String errorUri,
            AuthorizationRequest authentication,
            RegisteredClient registeredClient) {
        String redirectUri = resolveRedirectUri(authentication, registeredClient);
        if (OAuth2ErrorCodes.INVALID_REQUEST.equals(errorCode)
                && (OAuth2ParameterNames.CLIENT_ID.equals(parameterName)
                        || OAuth2ParameterNames.STATE.equals(parameterName))) {
            redirectUri = null;
        }

        throw new AuthorizationRequestException(
                new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri),
                redirectUri == null
                        ? null
                        : new AuthorizationRedirect(redirectUri, authentication.getState()));
    }

    private static String resolveRedirectUri(
            AuthorizationRequest authentication, RegisteredClient registeredClient) {
        if (Arguments.hasText(authentication.getRedirectUri())) {
            return authentication.getRedirectUri();
        }
        if (registeredClient != null && !registeredClient.getRedirectUris().isEmpty()) {
            return registeredClient.getRedirectUris().iterator().next();
        }
        return null;
    }
}
