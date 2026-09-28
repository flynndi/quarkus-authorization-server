package io.quarkiverse.authorization.server.oidc.session;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

/**
 * OIDC's immutable view of an authenticated application session, not a login credential.
 * The sessionId is a public, opaque identifier; never pass an HTTP session or credential cookie value.
 * The original authenticationTime remains unchanged when the Quarkus login session is used or renewed.
 */
public record SessionInformation(String principalName, String sessionId, Instant authenticationTime) implements Serializable {

    @Serial
    private static final long serialVersionUID = -874605856103462442L;

    public SessionInformation {
        if (principalName == null || principalName.isBlank() || sessionId == null || sessionId.isBlank()) {
            throw new IllegalArgumentException("principalName and sessionId cannot be empty");
        }
        Objects.requireNonNull(authenticationTime, "authenticationTime cannot be null");
    }
}
