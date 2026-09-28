package io.quarkiverse.authorization.server.runtime.client.authentication;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.inject.Singleton;

import org.jose4j.http.Get;
import org.jose4j.jwk.HttpsJwks;

import io.quarkiverse.authorization.server.runtime.util.Arguments;

/** Shared, bounded JWKS transport for registered client credentials. Call only from a worker. */
@Singleton
public final class ClientJwkSetCache {
    private static final int MAX_CACHED_JWK_SETS = 256;
    private static final int HTTP_TIMEOUT_MILLIS = 15_000;
    private static final long DEFAULT_CACHE_SECONDS = 300;
    private final Map<String, HttpsJwks> keys = Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, HttpsJwks> eldest) {
            return size() > MAX_CACHED_JWK_SETS;
        }
    });

    public HttpsJwks get(String location) {
        ClientJwkSetCache.validateJwkSetUrl(location);
        return this.keys.computeIfAbsent(location, ClientJwkSetCache::create);
    }

    public static void validateJwkSetUrl(String location) {
        URI uri = URI.create(Arguments.requireNonBlank(location, "jwkSetUrl"));
        if (!("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme()))
                || uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("jwkSetUrl must be an HTTP(S) URL without user info or fragment");
        }
    }

    private static HttpsJwks create(String location) {
        Get http = new Get();
        http.setConnectTimeout(HTTP_TIMEOUT_MILLIS);
        http.setReadTimeout(HTTP_TIMEOUT_MILLIS);
        http.setRetries(0);
        HttpsJwks keys = new HttpsJwks(location);
        keys.setSimpleHttpGet(http);
        keys.setDefaultCacheDuration(DEFAULT_CACHE_SECONDS);
        return keys;
    }
}
