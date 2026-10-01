package io.quarkiverse.authorization.server.runtime.client.authentication;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.URI;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.smallrye.common.net.Inet;

class ClientJwkSetUrlPolicyTest {
    private final ClientJwkSetUrlPolicy policy = new ClientJwkSetUrlPolicy(Set.of());

    @ParameterizedTest
    @ValueSource(strings = { "0.0.0.0", "0.1.2.3", "10.2.3.4", "100.64.0.1", "100.127.255.255", "127.0.0.1",
            "169.254.169.254", "172.16.0.1", "172.31.255.255", "192.0.0.8", "192.0.2.1", "192.88.99.1",
            "192.168.1.1", "198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.1", "224.0.0.1",
            "240.0.0.1", "255.255.255.255", "::", "::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "fc00::1",
            "fd00::1", "fe80::1", "fec0::1", "ff02::1", "64:ff9b::7f00:1", "2001::1", "2001:2::1",
            "2001:db8::1", "2002:7f00:1::", "3fff::1" })
    void rejectsNonPublicLiteralAndResolvedAddresses(String address) {
        InetAddress ip = Inet.parseInetAddressOrFail(address);
        assertFalse(ClientJwkSetUrlPolicy.isPublicAddress(ip));
        String host = address.contains(":") ? "[" + address + "]" : address;
        assertThrows(IllegalArgumentException.class, () -> this.policy.validate("https://" + host + "/jwks"));
        assertThrows(IllegalArgumentException.class, () -> this.policy.validateAddresses(
                URI.create("https://client.example/jwks"), new InetAddress[] { ip }));
    }

    @ParameterizedTest
    @ValueSource(strings = { "8.8.8.8", "1.1.1.1", "100.128.0.1", "172.32.0.1", "2001:4860:4860::8888", "2606:4700::1111" })
    void acceptsPublicAddresses(String address) {
        assertTrue(ClientJwkSetUrlPolicy.isPublicAddress(Inet.parseInetAddressOrFail(address)));
    }

    @ParameterizedTest
    @ValueSource(strings = { "http://client.example/jwks", "file:/tmp/keys", "//client.example/jwks",
            "https://user:pass@client.example/jwks", "https://client.example/jwks#fragment", "https://client.example:0/keys",
            "https://client.example:65536/keys", "https://[fe80::1%25en0]/keys", "https://localhost/keys",
            "https://localhost./keys", "https://sub.localhost/keys" })
    void rejectsUnsafeUrls(String url) {
        assertThrows(IllegalArgumentException.class, () -> this.policy.validate(url));
    }

    @Test
    void anyPrivateDnsAnswerRejectsTheDestinationAndRefreshMustRecheckIt() {
        URI uri = URI.create("https://client.example/jwks");
        InetAddress publicIp = Inet.parseInetAddressOrFail("8.8.8.8");
        InetAddress loopback = Inet.parseInetAddressOrFail("127.0.0.1");
        assertDoesNotThrow(() -> this.policy.validateAddresses(uri, new InetAddress[] { publicIp }));
        assertThrows(IllegalArgumentException.class,
                () -> this.policy.validateAddresses(uri, new InetAddress[] { publicIp, loopback }));
        assertThrows(IllegalArgumentException.class,
                () -> this.policy.validateAddresses(uri, new InetAddress[] { loopback }));
        assertThrows(IllegalArgumentException.class, () -> this.policy.validateAddresses(uri, new InetAddress[0]));
    }

    @Test
    void privateExceptionsAreExactHttpsOriginsNotHostSuffixesOrSchemeExceptions() {
        var approved = new ClientJwkSetUrlPolicy(Set.of("https://localhost:8443", "https://127.0.0.1"));
        assertDoesNotThrow(() -> approved.validate("https://LOCALHOST.:8443/jwks?version=2"));
        assertDoesNotThrow(() -> approved.validate("https://127.0.0.1:443/jwks"));
        assertThrows(IllegalArgumentException.class, () -> approved.validate("https://localhost:8444/jwks"));
        assertThrows(IllegalArgumentException.class, () -> approved.validate("https://sub.localhost:8443/jwks"));
        assertThrows(IllegalArgumentException.class, () -> approved.validate("http://localhost:8443/jwks"));
        assertThrows(IllegalArgumentException.class, () -> new ClientJwkSetUrlPolicy(Set.of("https://localhost/path")));
        assertThrows(IllegalArgumentException.class, () -> new ClientJwkSetUrlPolicy(Set.of("http://localhost")));
    }
}
