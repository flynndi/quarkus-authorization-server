package io.quarkiverse.authorization.server.dpop;

import java.time.Instant;
import java.util.Objects;

/** Validated key binding and bounded replay data; does not retain the raw JWT or public key. */
public record DPoPProof(String jwkThumbprint, String jwtId, Instant expiresAt) {
    public DPoPProof {
        Objects.requireNonNull(jwkThumbprint, "jwkThumbprint");
        Objects.requireNonNull(jwtId, "jwtId");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }
}
