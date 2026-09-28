package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkus.arc.Arc;
import io.quarkus.runtime.BlockingOperationControl;
import io.vertx.core.Context;

/** Exercises request-scoped application dependencies through real endpoint policy invocations. */
@RequestScoped
public class PolicyRequestProbe {
    private final UUID id = UUID.randomUUID();
    @Inject
    Observations observations;

    public void visit(String stage) {
        assertTrue(Arc.container().requestContext().isActive());
        assertTrue(BlockingOperationControl.isBlockingAllowed());
        assertFalse(Context.isOnEventLoopThread());
        this.observations.visits.computeIfAbsent(this.id, ignored -> new CopyOnWriteArrayList<>()).add(stage);
    }

    @PreDestroy
    void destroy() {
        this.observations.destroyed.add(this.id);
    }

    @Singleton
    public static class Observations {
        final ConcurrentHashMap<UUID, List<String>> visits = new ConcurrentHashMap<>();
        final Set<UUID> destroyed = ConcurrentHashMap.newKeySet();

        void clear() {
            assertTrue(this.destroyed.containsAll(this.visits.keySet()), "Previous policy request scope was not released");
            this.visits.clear();
            this.destroyed.clear();
        }

        void assertReleased(List<String> stages) {
            assertTrue(this.visits.values().contains(stages), this.visits.toString());
            assertTrue(this.destroyed.containsAll(this.visits.keySet()), "A policy request scope was not released");
        }
    }
}
