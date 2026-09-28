package io.quarkiverse.authorization.server.runtime.dpop;

import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Objects;
import java.util.PriorityQueue;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.dpop.DPoPReplayStore;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkus.arc.DefaultBean;

/** Bounded single-JVM store. No active-entry eviction, scheduler, or cluster guarantee. */
@Singleton
@DefaultBean
public final class InMemoryDPoPReplayStore implements DPoPReplayStore {
    private final Set<Key> entries = new HashSet<>();
    private final PriorityQueue<Expiry> expirations = new PriorityQueue<>(Comparator.comparing(Expiry::at));
    private final Clock clock;
    private final int maxSize;
    private Instant lastObservedTime = Instant.MIN;

    @Inject
    public InMemoryDPoPReplayStore(AuthorizationServerRuntimeConfig config) {
        this(config.dpop().replayCacheSize(), Clock.systemUTC());
    }

    InMemoryDPoPReplayStore(int maxSize, Clock clock) {
        if (maxSize <= 0)
            throw new IllegalArgumentException("dpop.replay-cache-size must be positive");
        this.maxSize = maxSize;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public synchronized boolean claim(Key key, Instant expiresAt) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Instant now = clock.instant();
        // A backwards wall clock must not make previously expired and removed proofs reusable.
        if (now.isBefore(lastObservedTime))
            return false;
        lastObservedTime = now;
        if (!now.isBefore(expiresAt))
            return false;
        while (!expirations.isEmpty() && !now.isBefore(expirations.peek().at())) {
            Expiry expired = expirations.remove();
            entries.remove(expired.key());
        }
        // Capacity and insertion share the lock: concurrent new keys cannot exceed the bound.
        if (entries.contains(key) || entries.size() >= maxSize)
            return false;
        entries.add(key);
        expirations.add(new Expiry(key, expiresAt));
        return true;
    }

    private record Expiry(Key key, Instant at) {
    }
}
