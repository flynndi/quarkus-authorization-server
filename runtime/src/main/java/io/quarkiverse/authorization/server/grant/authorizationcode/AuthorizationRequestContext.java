package io.quarkiverse.authorization.server.grant.authorizationcode;

import java.util.Objects;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;

/**
 * Request validation context; authorization request and prior consent are populated for the consent
 * decision.
 */
public final class AuthorizationRequestContext {
    private final AuthorizationRequest request;
    private final RegisteredClient registeredClient;
    private final OAuth2AuthorizationRequest authorizationRequest;
    private final OAuth2AuthorizationConsent authorizationConsent;

    private AuthorizationRequestContext(Builder builder) {
        this.request = Objects.requireNonNull(builder.request, "request cannot be null");
        this.registeredClient = Objects.requireNonNull(builder.registeredClient, "registeredClient cannot be null");
        this.authorizationRequest = builder.authorizationRequest;
        this.authorizationConsent = builder.authorizationConsent;
    }

    public AuthorizationRequest getRequest() {
        return this.request;
    }

    public RegisteredClient getRegisteredClient() {
        return this.registeredClient;
    }

    public OAuth2AuthorizationRequest getAuthorizationRequest() {
        return this.authorizationRequest;
    }

    public OAuth2AuthorizationConsent getAuthorizationConsent() {
        return this.authorizationConsent;
    }

    public static Builder with(AuthorizationRequest request) {
        return new Builder(request);
    }

    public static final class Builder {
        private final AuthorizationRequest request;
        private RegisteredClient registeredClient;
        private OAuth2AuthorizationRequest authorizationRequest;
        private OAuth2AuthorizationConsent authorizationConsent;

        private Builder(AuthorizationRequest request) {
            this.request = Objects.requireNonNull(request, "request cannot be null");
        }

        public Builder registeredClient(RegisteredClient registeredClient) {
            this.registeredClient = registeredClient;
            return this;
        }

        public Builder authorizationRequest(OAuth2AuthorizationRequest authorizationRequest) {
            this.authorizationRequest = authorizationRequest;
            return this;
        }

        public Builder authorizationConsent(OAuth2AuthorizationConsent authorizationConsent) {
            this.authorizationConsent = authorizationConsent;
            return this;
        }

        public AuthorizationRequestContext build() {
            return new AuthorizationRequestContext(this);
        }
    }
}
