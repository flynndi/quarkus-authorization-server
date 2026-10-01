package io.quarkiverse.authorization.server.runtime.client.authentication;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.smallrye.common.net.CidrAddress;
import io.smallrye.common.net.Inet;

/** Applies the same destination policy to client registration and every remote JWKS fetch. */
@Singleton
public final class ClientJwkSetUrlPolicy {
    private static final List<CidrAddress> NON_PUBLIC = List.of(
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
            "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
            "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
            "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20")
            .stream().map(Inet::parseCidrAddress).toList();
    private static final CidrAddress IPV6_GLOBAL_UNICAST = Inet.parseCidrAddress("2000::/3");
    private final Set<String> allowedPrivateOrigins;

    @Inject
    public ClientJwkSetUrlPolicy(AuthorizationServerRuntimeConfig config) {
        this(config.clientJwks().allowedPrivateOrigins().orElse(Set.of()));
    }

    public ClientJwkSetUrlPolicy(Set<String> allowedPrivateOrigins) {
        this.allowedPrivateOrigins = allowedPrivateOrigins.stream().map(value -> {
            URI uri = ClientJwkSetUrlPolicy.parse(value);
            if (uri.getRawQuery() != null || !(uri.getRawPath().isEmpty() || "/".equals(uri.getRawPath()))) {
                throw new IllegalArgumentException("client-jwks.allowed-private-origins must contain HTTPS origins only");
            }
            return ClientJwkSetUrlPolicy.origin(uri);
        }).collect(Collectors.toUnmodifiableSet());
    }

    public static URI parse(String location) {
        URI uri = URI.create(Arguments.requireNonBlank(location, "jwkSetUrl"));
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null
                || uri.getRawFragment() != null || uri.getHost().contains("%") || uri.getPort() == 0
                || uri.getPort() < -1 || uri.getPort() > 65535) {
            throw new IllegalArgumentException("jwkSetUrl must be an HTTPS URL without user info, fragment or zone identifier");
        }
        return uri;
    }

    /** No network access during metadata validation. DNS answers are checked again immediately before connecting. */
    public URI validate(String location) {
        URI uri = ClientJwkSetUrlPolicy.parse(location);
        if (!this.allowedPrivateOrigins.contains(ClientJwkSetUrlPolicy.origin(uri))) {
            String host = ClientJwkSetUrlPolicy.host(uri);
            InetAddress literal = Inet.parseInetAddress(host);
            if (host.equals("localhost") || host.endsWith(".localhost")
                    || literal != null && !ClientJwkSetUrlPolicy.isPublicAddress(literal)) {
                throw new IllegalArgumentException("jwkSetUrl destination is not permitted");
            }
        }
        return uri;
    }

    void validateAddresses(URI uri, InetAddress[] addresses) {
        if (addresses.length == 0) {
            throw new IllegalArgumentException("jwkSetUrl has no resolved addresses");
        }
        if (!this.allowedPrivateOrigins.contains(ClientJwkSetUrlPolicy.origin(uri))) {
            for (InetAddress address : addresses) {
                if (!ClientJwkSetUrlPolicy.isPublicAddress(address)) {
                    throw new IllegalArgumentException("jwkSetUrl resolved to a prohibited address");
                }
            }
        }
    }

    static boolean isPublicAddress(InetAddress address) {
        return (address instanceof Inet4Address || IPV6_GLOBAL_UNICAST.matches(address))
                && NON_PUBLIC.stream().noneMatch(range -> range.matches(address));
    }

    static String host(URI uri) {
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if (host.startsWith("["))
            host = host.substring(1, host.length() - 1);
        return host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
    }

    private static String origin(URI uri) {
        return ClientJwkSetUrlPolicy.host(uri) + ":" + (uri.getPort() == -1 ? 443 : uri.getPort());
    }
}
