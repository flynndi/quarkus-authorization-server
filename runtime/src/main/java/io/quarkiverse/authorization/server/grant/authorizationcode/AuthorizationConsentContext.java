package io.quarkiverse.authorization.server.grant.authorizationcode;

import java.util.Objects;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;

/**
 * Holds an Authorization Consent and the associated authorization state while consent is
 * customized.
 */
public final class AuthorizationConsentContext {

    /** Final request decision, independent of the consent authorities being persisted. */
    public enum Decision {
        APPROVE,
        DENY
    }

    private final ConsentSubmission submission;
    private final OAuth2AuthorizationConsent.Builder authorizationConsent;
    private final RegisteredClient registeredClient;
    private final OAuth2Authorization authorization;
    private final OAuth2AuthorizationRequest authorizationRequest;
    private Decision decision;

    private AuthorizationConsentContext(Builder builder) {
        this.submission = builder.submission;
        this.authorizationConsent = builder.authorizationConsent;
        this.registeredClient = builder.registeredClient;
        this.authorization = builder.authorization;
        this.authorizationRequest = builder.authorizationRequest;
        this.decision = this.submission.isDenied() ? Decision.DENY : Decision.APPROVE;
    }

    public ConsentSubmission getSubmission() {
        return this.submission;
    }

    public OAuth2AuthorizationConsent.Builder getAuthorizationConsent() {
        return this.authorizationConsent;
    }

    public RegisteredClient getRegisteredClient() {
        return this.registeredClient;
    }

    public OAuth2Authorization getAuthorization() {
        return this.authorization;
    }

    public OAuth2AuthorizationRequest getAuthorizationRequest() {
        return this.authorizationRequest;
    }

    public Decision getDecision() {
        return this.decision;
    }

    /**
     * Customize the final request decision without changing the original submission.
     * DENY preserves existing consent unless the customizer also clears all authorities;
     * empty authorities revoke consent regardless of this decision.
     */
    public void setDecision(Decision decision) {
        this.decision = Objects.requireNonNull(decision, "decision cannot be null");
    }

    public static Builder with(ConsentSubmission submission) {
        return new Builder(submission);
    }

    public static final class Builder {

        private final ConsentSubmission submission;
        private OAuth2AuthorizationConsent.Builder authorizationConsent;
        private RegisteredClient registeredClient;
        private OAuth2Authorization authorization;
        private OAuth2AuthorizationRequest authorizationRequest;

        private Builder(ConsentSubmission submission) {
            this.submission = Objects.requireNonNull(submission, "submission cannot be null");
        }

        public Builder authorizationConsent(
                OAuth2AuthorizationConsent.Builder authorizationConsent) {
            this.authorizationConsent = authorizationConsent;
            return this;
        }

        public Builder registeredClient(RegisteredClient registeredClient) {
            this.registeredClient = registeredClient;
            return this;
        }

        public Builder authorization(OAuth2Authorization authorization) {
            this.authorization = authorization;
            return this;
        }

        public Builder authorizationRequest(OAuth2AuthorizationRequest authorizationRequest) {
            this.authorizationRequest = authorizationRequest;
            return this;
        }

        public AuthorizationConsentContext build() {
            Objects.requireNonNull(
                    this.authorizationConsent, "authorizationConsent cannot be null");
            Objects.requireNonNull(this.registeredClient, "registeredClient cannot be null");
            Objects.requireNonNull(this.authorization, "authorization cannot be null");
            if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(
                    this.authorization.getAuthorizationGrantType())) {
                Objects.requireNonNull(
                        this.authorizationRequest, "authorizationRequest cannot be null");
            }
            return new AuthorizationConsentContext(this);
        }
    }
}
