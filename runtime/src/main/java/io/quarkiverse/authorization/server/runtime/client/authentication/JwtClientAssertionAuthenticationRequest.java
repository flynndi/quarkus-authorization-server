package io.quarkiverse.authorization.server.runtime.client.authentication;

import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkus.security.identity.request.BaseAuthenticationRequest;

/** An unverified client assertion. The registered client determines its authentication method. */
public final class JwtClientAssertionAuthenticationRequest extends BaseAuthenticationRequest {
    public static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private final String clientId;
    private final String assertion;

    public JwtClientAssertionAuthenticationRequest(String clientId, String assertion) {
        this.clientId = Arguments.requireNonBlank(clientId, "clientId");
        this.assertion = Arguments.requireNonBlank(assertion, "assertion");
    }

    public String getClientId() {
        return this.clientId;
    }

    public String getAssertion() {
        return this.assertion;
    }
}
