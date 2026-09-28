package io.quarkiverse.authorization.server.runtime.dpop;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.time.*;
import java.util.ArrayList;
import java.util.concurrent.*;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.dpop.DPoPReplayStore;

class InMemoryDPoPReplayStoreTest {
    @Test
    void rejectsDuplicatesAndFullCapacityWithoutEvictingActiveProofs() {
        MutableClock clock = new MutableClock();
        var store = new InMemoryDPoPReplayStore(1, clock);
        Instant expiry = clock.instant().plusSeconds(60);
        assertTrue(store.claim(key("first"), expiry));
        assertFalse(store.claim(key("first"), expiry.plusSeconds(10)));
        assertFalse(store.claim(key("second"), expiry));
        assertFalse(store.claim(key("first"), expiry));
        clock.now = expiry;
        assertFalse(store.claim(key("expired"), expiry));
        assertTrue(store.claim(key("second"), expiry.plusSeconds(60)));
        assertFalse(store.claim(key("second"), expiry.plusSeconds(60)));
    }

    @Test
    void clockRollbackCannotResurrectAnEvictedProof() {
        MutableClock clock = new MutableClock();
        var store = new InMemoryDPoPReplayStore(1, clock);
        Instant initial = clock.instant();
        assertTrue(store.claim(key("first"), initial.plusSeconds(30)));
        clock.now = initial.plusSeconds(31);
        assertTrue(store.claim(key("second"), initial.plusSeconds(60)));
        clock.now = initial;
        assertFalse(store.claim(key("first"), initial.plusSeconds(30)));
        clock.now = initial.plusSeconds(61);
        assertTrue(store.claim(key("third"), initial.plusSeconds(90)));
    }

    @Test
    void namespacesKeysByTargetAndPublicKey() {
        MutableClock clock = new MutableClock();
        var store = new InMemoryDPoPReplayStore(3, clock);
        Instant expiry = clock.instant().plusSeconds(60);
        assertTrue(store.claim(key("id"), expiry));
        assertTrue(
                store.claim(
                        new DPoPReplayStore.Key(
                                URI.create("https://resource.example/api"), "key", "id"),
                        expiry));
        assertTrue(
                store.claim(
                        new DPoPReplayStore.Key(DPoPProofVerifierTest.TOKEN_URI, "other-key", "id"),
                        expiry));
        assertFalse(
                store.claim(
                        new DPoPReplayStore.Key(
                                URI.create("https://SERVER.example:443/oauth2/token?ignored"),
                                "key",
                                "id"),
                        expiry));
    }

    @Test
    void concurrentUseAndCapacityAreAtomic() throws Exception {
        MutableClock clock = new MutableClock();
        var store = new InMemoryDPoPReplayStore(10, clock);
        Instant expiry = clock.instant().plusSeconds(60);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            CountDownLatch start = new CountDownLatch(1);
            var futures = new ArrayList<Future<Boolean>>();
            for (int i = 0; i < 64; i++)
                futures.add(
                        executor.submit(
                                () -> {
                                    start.await();
                                    return store.claim(key("shared"), expiry);
                                }));
            start.countDown();
            int accepted = 0;
            for (var future : futures)
                if (future.get(5, TimeUnit.SECONDS))
                    accepted++;
            assertEquals(1, accepted);
            futures.clear();
            for (int i = 0; i < 64; i++) {
                String id = "unique-" + i;
                futures.add(executor.submit(() -> store.claim(key(id), expiry)));
            }
            accepted = 0;
            for (var future : futures)
                if (future.get(5, TimeUnit.SECONDS))
                    accepted++;
            assertEquals(9, accepted);
            assertFalse(store.claim(key("shared"), expiry));
        }
    }

    private static DPoPReplayStore.Key key(String id) {
        return new DPoPReplayStore.Key(DPoPProofVerifierTest.TOKEN_URI, "key", id);
    }

    private static class MutableClock extends Clock {
        Instant now = DPoPProofVerifierTest.NOW;

        public Instant instant() {
            return now;
        }

        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        public Clock withZone(ZoneId zone) {
            return this;
        }
    }
}
