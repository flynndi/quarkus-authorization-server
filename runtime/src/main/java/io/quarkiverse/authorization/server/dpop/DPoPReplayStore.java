package io.quarkiverse.authorization.server.dpop;

import java.net.URI;
import java.time.Instant;
import java.util.Objects;

import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofRequest;

/** Atomic proof-use registration. Applications may replace the default with a shared CDI store. */
public interface DPoPReplayStore {
    /**
     * Atomically retains this key until expiresAt (exclusive). Returns true only for the first use.
     * Full/expired stores must reject, never evict still-valid keys to admit another request.
     * Backend failures must fail the request. Call after proof and token/client binding validation.
     */
    boolean claim(Key key, Instant expiresAt);

    /**
     * Target URI includes the origin/path and excludes query/fragment; distinct services are
     * isolated.
     */
    record Key(URI targetUri, String jwkThumbprint, String jwtId) {
        public Key {
            targetUri = DPoPProofRequest.canonicalUri(targetUri);
            Objects.requireNonNull(jwkThumbprint, "jwkThumbprint");
            Objects.requireNonNull(jwtId, "jwtId");
        }
    }
}
