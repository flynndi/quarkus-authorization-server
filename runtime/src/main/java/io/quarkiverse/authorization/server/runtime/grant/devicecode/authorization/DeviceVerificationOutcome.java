package io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

import io.quarkus.security.identity.SecurityIdentity;

/** Explicit results of user-code verification and consent, independent of HTTP rendering. */
public sealed interface DeviceVerificationOutcome {
    record Approved(String clientId) implements DeviceVerificationOutcome {
        public Approved {
            Objects.requireNonNull(clientId, "clientId cannot be null");
        }
    }

    /** authorizedScopes need no new scope selection; this device still requires confirmation. */
    record ConfirmationRequired(
            String clientId,
            SecurityIdentity principal,
            Set<String> requestedScopes,
            Set<String> authorizedScopes,
            String userCode,
            String state)
            implements
                DeviceVerificationOutcome {
        public ConfirmationRequired {
            Objects.requireNonNull(clientId, "clientId cannot be null");
            Objects.requireNonNull(principal, "principal cannot be null");
            Objects.requireNonNull(userCode, "userCode cannot be null");
            Objects.requireNonNull(state, "state cannot be null");
            requestedScopes = Collections.unmodifiableSet(new LinkedHashSet<>(requestedScopes));
            authorizedScopes = Collections.unmodifiableSet(new LinkedHashSet<>(authorizedScopes));
        }
    }
}
