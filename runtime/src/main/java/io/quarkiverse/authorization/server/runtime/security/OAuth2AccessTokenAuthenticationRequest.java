package io.quarkiverse.authorization.server.runtime.security;

import java.util.Objects;

import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofRequest;
import io.quarkus.security.credential.TokenCredential;
import io.quarkus.security.identity.request.BaseAuthenticationRequest;

/** A local access-token request, distinct from external resource-server JWT/OIDC requests. */
public final class OAuth2AccessTokenAuthenticationRequest extends BaseAuthenticationRequest {
    public static final String BEARER = "bearer";
    public static final String DPOP = "dpop";
    private final TokenCredential token;
    private final DPoPProofRequest proof;

    public OAuth2AccessTokenAuthenticationRequest(TokenCredential token) {
        this(token, null);
    }

    public OAuth2AccessTokenAuthenticationRequest(TokenCredential token, DPoPProofRequest proof) {
        this.token = Objects.requireNonNull(token, "token cannot be null");
        this.proof = proof;
    }

    public TokenCredential getToken() {
        return this.token;
    }

    public DPoPProofRequest getProof() {
        return this.proof;
    }
}
