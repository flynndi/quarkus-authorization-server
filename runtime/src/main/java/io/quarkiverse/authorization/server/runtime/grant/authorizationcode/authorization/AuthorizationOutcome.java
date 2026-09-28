package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import java.util.Objects;
import java.util.Set;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkus.security.identity.SecurityIdentity;

/** Protocol outcomes, independent of HTTP rendering and authentication request state. */
public sealed interface AuthorizationOutcome {
    record CodeIssued(
            OAuth2AuthorizationCode code, String redirectUri, String state, Set<String> scopes)
            implements
                AuthorizationOutcome {
        public CodeIssued {
            Objects.requireNonNull(code, "code cannot be null");
            Objects.requireNonNull(redirectUri, "redirectUri cannot be null");
            scopes = Set.copyOf(scopes);
        }
    }

    record ConsentRequired(
            String authorizationUri,
            String clientId,
            SecurityIdentity principal,
            String state,
            Set<String> requestedScopes,
            Set<String> authorizedScopes)
            implements
                AuthorizationOutcome {
        public ConsentRequired {
            Objects.requireNonNull(authorizationUri, "authorizationUri cannot be null");
            Objects.requireNonNull(clientId, "clientId cannot be null");
            Objects.requireNonNull(principal, "principal cannot be null");
            Objects.requireNonNull(state, "state cannot be null");
            requestedScopes = Set.copyOf(requestedScopes);
            authorizedScopes = authorizedScopes == null ? Set.of() : Set.copyOf(authorizedScopes);
        }
    }

    /** HTTP authentication normally handles this before the protocol adapter is called. */
    record LoginRequired() implements AuthorizationOutcome {
    }
}
