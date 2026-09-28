package io.quarkiverse.authorization.server.runtime.dpop;

import java.time.Clock;

/** Real proof and replay services for synchronous protocol tests, without starting Quarkus. */
public final class DPoPTestSupport {
    private DPoPTestSupport() {
    }

    public static DPoPTokenBinding binding() {
        return new DPoPTokenBinding(
                new DPoPProofVerifier(DPoPProofVerifierTest.config(), Clock.systemUTC()),
                new InMemoryDPoPReplayStore(100000, Clock.systemUTC()));
    }
}
