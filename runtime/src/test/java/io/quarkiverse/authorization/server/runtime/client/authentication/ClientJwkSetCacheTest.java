package io.quarkiverse.authorization.server.runtime.client.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import io.vertx.core.Promise;
import io.vertx.core.http.HttpClientOptions;

class ClientJwkSetCacheTest {
    @Test
    void rejectedUrlsAndDnsAliasesNeverReachTheLocalServer() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        try (var server = new ClientJwksTestServer(request -> {
            requests.incrementAndGet();
            request.response().end("{\"keys\":[]}");
        })) {
            var cache = server.cache(Set.of());
            int port = server.server.actualPort();
            for (String host : new String[] { "localhost", "127.0.0.1", "[::1]", "2130706433", "127.1" }) {
                assertThrows(Exception.class, () -> cache.get("https://" + host + ":" + port + "/jwks").getJsonWebKeys());
            }
            assertThrows(IllegalArgumentException.class,
                    () -> cache.get(server.origin().replace("https:", "http:") + "/jwks"));
            assertEquals(0, requests.get());
        }
    }

    @Test
    void permittedTlsRequestRetainsHostAndCachesTheKeys() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        try (var server = new ClientJwksTestServer(request -> {
            requests.incrementAndGet();
            assertEquals("localhost:" + request.localAddress().port(), request.getHeader("Host"));
            request.response().putHeader("Cache-Control", "max-age=300").end("{\"keys\":[]}");
        })) {
            var keys = server.cache(Set.of(server.origin())).get(server.origin() + "/jwks");
            assertEquals(0, keys.getJsonWebKeys().size());
            assertEquals(0, keys.getJsonWebKeys().size());
            assertEquals(1, requests.get());
        }
    }

    @Test
    void redirectsAreRejectedWithoutContactingTheirTarget() throws Exception {
        AtomicInteger targetRequests = new AtomicInteger();
        try (var server = new ClientJwksTestServer(request -> {
            if ("/redirect".equals(request.path())) {
                request.response().setStatusCode(302).putHeader("Location", "/target").end();
            } else {
                targetRequests.incrementAndGet();
                request.response().end("{\"keys\":[]}");
            }
        })) {
            var keys = server.cache(Set.of(server.origin())).get(server.origin() + "/redirect");
            assertThrows(IOException.class, keys::getJsonWebKeys);
            assertEquals(0, targetRequests.get());
        }
    }

    @Test
    void boundsResponseSizeAndRequiresTrustedTlsEvenForApprovedOrigins() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        try (var server = new ClientJwksTestServer(request -> {
            requests.incrementAndGet();
            request.response().end(" ".repeat(512 * 1024 + 1));
        })) {
            var untrusted = new ClientJwkSetCache(server.vertx.createHttpClient(new HttpClientOptions().setVerifyHost(true)),
                    new ClientJwkSetUrlPolicy(Set.of(server.origin())));
            assertThrows(IOException.class, () -> untrusted.get(server.origin() + "/jwks").getJsonWebKeys());
            assertEquals(0, requests.get());
            var trusted = server.cache(Set.of(server.origin()));
            assertThrows(IOException.class, () -> trusted.get(server.origin() + "/jwks").getJsonWebKeys());
            assertEquals(1, requests.get());
        }
    }

    @Test
    void interruptedHandshakeDoesNotSendALateRequestAndReleasesThePoolSlot() throws Exception {
        var paths = new CopyOnWriteArrayList<String>();
        try (var server = new ClientJwksTestServer(request -> {
            paths.add(request.path());
            request.response().end("{\"keys\":[]}");
        })) {
            // Hold the TCP tunnel before TLS can complete, then release it after the worker has returned.
            Promise<Void> accepted = Promise.promise();
            Promise<Void> release = Promise.promise();
            var upstream = server.vertx.createNetClient();
            var proxy = server.vertx.createNetServer().connectHandler(socket -> {
                socket.pause();
                accepted.tryComplete();
                release.future().compose(ignored -> upstream.connect(server.server.actualPort(), "127.0.0.1"))
                        .onSuccess(target -> {
                            target.pipeTo(socket);
                            socket.pipeTo(target);
                        }).onFailure(failure -> socket.close());
            }).listen(0, "127.0.0.1").toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
            String origin = "https://localhost:" + proxy.actualPort();
            var cache = server.cache(Set.of(origin), new HttpClientOptions().setMaxPoolSize(1));
            CompletableFuture<Exception> outcome = new CompletableFuture<>();
            AtomicBoolean interrupted = new AtomicBoolean();
            Thread worker = new Thread(() -> {
                Exception failure = null;
                try {
                    cache.get(origin + "/cancelled").getJsonWebKeys();
                } catch (Exception exception) {
                    failure = exception;
                } finally {
                    interrupted.set(Thread.currentThread().isInterrupted());
                    outcome.complete(failure);
                }
            }, "interrupted-jwks-download");
            worker.start();
            try {
                accepted.future().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
                worker.interrupt();
                IOException failure = assertInstanceOf(IOException.class, outcome.get(5, TimeUnit.SECONDS));
                assertInstanceOf(InterruptedException.class, failure.getCause());
                assertTrue(interrupted.get());
                release.complete();
                // One pool slot forces this request to wait for the interrupted request to release its slot.
                assertTrue(cache.get(origin + "/probe").getJsonWebKeys().isEmpty());
                assertEquals(List.of("/probe"), paths);
            } finally {
                release.tryComplete();
                worker.interrupt();
                worker.join(5_000);
            }
        }
    }
}
