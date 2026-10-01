package io.quarkiverse.authorization.server.runtime.client.authentication;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import jakarta.annotation.PreDestroy;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jose4j.http.Response;
import org.jose4j.http.SimpleResponse;
import org.jose4j.jwk.HttpsJwks;

import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkus.runtime.Startup;
import io.quarkus.tls.TlsConfiguration;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.quarkus.tls.runtime.config.TlsConfigUtils;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.net.SocketAddress;

/** Shared, bounded JWKS transport for registered client credentials. Call only from a worker. */
@Singleton
@Startup
public final class ClientJwkSetCache {
    private static final int MAX_CACHED_JWK_SETS = 256;
    private static final int HTTP_TIMEOUT_MILLIS = 15_000;
    private static final int MAX_RESPONSE_BYTES = 512 * 1024;
    private static final long DEFAULT_CACHE_SECONDS = 300;
    private final HttpClient http;
    private final ClientJwkSetUrlPolicy policy;
    private final Map<String, HttpsJwks> keys = Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, HttpsJwks> eldest) {
            return size() > MAX_CACHED_JWK_SETS;
        }
    });

    @Inject
    public ClientJwkSetCache(Vertx vertx, AuthorizationServerRuntimeConfig config, TlsConfigurationRegistry tls,
            ClientJwkSetUrlPolicy policy) {
        this(ClientJwkSetCache.createHttpClient(vertx, config, tls), policy);
    }

    public ClientJwkSetCache(HttpClient http, ClientJwkSetUrlPolicy policy) {
        this.http = http;
        this.policy = policy;
    }

    public HttpsJwks get(String location) {
        this.policy.validate(location);
        return this.keys.computeIfAbsent(location, this::create);
    }

    public static void validateJwkSetUrl(String location) {
        ClientJwkSetUrlPolicy.parse(location);
    }

    private HttpsJwks create(String location) {
        HttpsJwks keys = new HttpsJwks(location);
        keys.setSimpleHttpGet(this::fetch);
        keys.setDefaultCacheDuration(DEFAULT_CACHE_SECONDS);
        return keys;
    }

    private SimpleResponse fetch(String location) throws IOException {
        PendingRequest pending = new PendingRequest();
        try {
            URI uri = this.policy.validate(location);
            String host = ClientJwkSetUrlPolicy.host(uri);
            InetAddress[] addresses = InetAddress.getAllByName(host);
            this.policy.validateAddresses(uri, addresses);
            int port = uri.getPort() == -1 ? 443 : uri.getPort();
            String path = uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
            if (uri.getRawQuery() != null)
                path += "?" + uri.getRawQuery();
            // Pin the checked IP, retaining the logical host for Host/SNI and certificate verification.
            // No proxy, redirect or second hostname lookup may choose a different destination.
            RequestOptions options = new RequestOptions().setSsl(true).setHost(host).setPort(port).setURI(path)
                    .setServer(SocketAddress.inetSocketAddress(port, addresses[0].getHostAddress()))
                    // Preserve jose4j Get's revalidation semantics when an unknown kid forces a refresh.
                    .putHeader("Cache-Control", "no-cache")
                    .setFollowRedirects(false).setTimeout(HTTP_TIMEOUT_MILLIS);
            return this.http.request(options).compose(pending::send)
                    .toCompletionStage().toCompletableFuture().get(HTTP_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (Exception exception) {
            pending.cancel();
            if (exception instanceof InterruptedException)
                Thread.currentThread().interrupt();
            throw new IOException("Unable to retrieve permitted client JWKS", exception);
        }
    }

    /** Serializes cancellation with sending, including connections acquired after the worker stops waiting. */
    private static final class PendingRequest {
        private HttpClientRequest request;
        private boolean cancelled;

        synchronized Future<SimpleResponse> send(HttpClientRequest request) {
            if (this.cancelled) {
                request.reset();
                return Future.failedFuture(new IOException("Client JWKS request was cancelled"));
            }
            this.request = request;
            return request.send().compose(response -> ClientJwkSetCache.read(request, response));
        }

        synchronized void cancel() {
            this.cancelled = true;
            if (this.request != null) {
                this.request.reset();
            }
        }
    }

    private static Future<SimpleResponse> read(HttpClientRequest request, HttpClientResponse response) {
        if (response.statusCode() != 200) {
            request.reset();
            return Future.failedFuture(new IOException("Client JWKS endpoint must return HTTP 200 without redirection"));
        }
        Promise<SimpleResponse> result = Promise.promise();
        Buffer body = Buffer.buffer();
        response.exceptionHandler(result::tryFail);
        response.handler(chunk -> {
            if (body.length() + chunk.length() > MAX_RESPONSE_BYTES) {
                result.tryFail(new IOException("Client JWKS response exceeds the size limit"));
                request.reset();
            } else if (!result.future().isComplete()) {
                body.appendBuffer(chunk);
            }
        });
        response.endHandler(ignored -> {
            Map<String, List<String>> headers = new LinkedHashMap<>();
            response.headers().names().forEach(name -> headers.put(name, response.headers().getAll(name)));
            result.tryComplete(new Response(response.statusCode(), response.statusMessage(), headers, body.toString()));
        });
        return result.future();
    }

    private static HttpClient createHttpClient(Vertx vertx, AuthorizationServerRuntimeConfig config,
            TlsConfigurationRegistry tls) {
        HttpClientOptions options = new HttpClientOptions().setConnectTimeout(HTTP_TIMEOUT_MILLIS);
        config.clientJwks().tlsConfigurationName().ifPresent(name -> {
            TlsConfiguration configuration = tls.get(name)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown client JWKS TLS configuration"));
            // Reject before applying: setTrustAll(false) cannot remove an installed trust-all TrustManager.
            if (configuration.isTrustAll()) {
                throw new IllegalArgumentException("Client JWKS requires certificate validation; quarkus.tls."
                        + name + ".trust-all=true is not allowed");
            }
            TlsConfigUtils.configure(options, configuration);
        });
        // JWKS carry authentication keys: HTTPS always verifies the certificate chain and hostname.
        return vertx.createHttpClient(options.setSsl(true).setTrustAll(false).setVerifyHost(true));
    }

    @PreDestroy
    public void close() {
        this.http.close();
    }
}
