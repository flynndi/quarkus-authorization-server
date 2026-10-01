package io.quarkiverse.authorization.server.runtime.client.authentication;

import java.util.Set;
import java.util.concurrent.TimeUnit;

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.net.PemTrustOptions;
import io.vertx.core.net.PfxOptions;

/** HTTPS fixture using the public test CA and server store from deployment's mtls fixtures. */
final class ClientJwksTestServer implements AutoCloseable {
    final Vertx vertx = Vertx.vertx();
    final HttpServer server;

    ClientJwksTestServer(Handler<HttpServerRequest> handler) throws Exception {
        this.server = this.vertx.createHttpServer(new HttpServerOptions().setSsl(true)
                .setPfxKeyCertOptions(new PfxOptions().setValue(ClientJwksTestServer.resource("server.p12"))
                        .setPassword("password")))
                .requestHandler(handler).listen(0, "127.0.0.1").toCompletionStage().toCompletableFuture()
                .get(5, TimeUnit.SECONDS);
    }

    String origin() {
        return "https://localhost:" + this.server.actualPort();
    }

    ClientJwkSetCache cache(Set<String> allowedOrigins) throws Exception {
        return this.cache(allowedOrigins, new HttpClientOptions());
    }

    ClientJwkSetCache cache(Set<String> allowedOrigins, HttpClientOptions options) throws Exception {
        return new ClientJwkSetCache(this.vertx.createHttpClient(options
                .setVerifyHost(true)
                .setTrustOptions(new PemTrustOptions().addCertValue(ClientJwksTestServer.resource("ca.pem")))),
                new ClientJwkSetUrlPolicy(allowedOrigins));
    }

    private static Buffer resource(String name) throws Exception {
        try (var resource = ClientJwksTestServer.class.getResourceAsStream("/jwks/" + name)) {
            return Buffer.buffer(resource.readAllBytes());
        }
    }

    @Override
    public void close() throws Exception {
        this.vertx.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
    }
}
