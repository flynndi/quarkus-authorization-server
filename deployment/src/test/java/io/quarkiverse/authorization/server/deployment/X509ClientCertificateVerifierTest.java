package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.runtime.client.authentication.ClientJwkSetCache;
import io.quarkiverse.authorization.server.runtime.client.authentication.X509ClientCertificateVerifier;
import io.quarkiverse.authorization.server.settings.ClientSettings;

class X509ClientCertificateVerifierTest {
    private final ClientJwkSetCache cache = new ClientJwkSetCache();
    private final X509ClientCertificateVerifier verifier = new X509ClientCertificateVerifier(this.cache);
    private final AtomicReference<String> jwks = new AtomicReference<>();
    private final AtomicInteger requests = new AtomicInteger();
    private HttpServer server;
    private String url;

    @BeforeEach
    void startJwks() throws Exception {
        this.jwks.set(ClientCertificateTestSupport.jwks("self-client", "self-ec"));
        this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        this.server.createContext("/jwks", exchange -> {
            this.requests.incrementAndGet();
            byte[] bytes = this.jwks.get().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Cache-Control", "max-age=300");
            exchange.sendResponseHeaders(200, bytes.length);
            try (var output = exchange.getResponseBody()) {
                output.write(bytes);
            }
        });
        this.server.start();
        this.url = "http://localhost:" + this.server.getAddress().getPort() + "/jwks";
    }

    @AfterEach
    void stopJwks() {
        if (this.server != null)
            this.server.stop(0);
    }

    @Test
    void matchesRsaAndEcCertificatesAndCachesOnlyTheRegisteredJwks() throws Exception {
        RegisteredClient client = X509ClientCertificateVerifierTest.client(
                ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
                ClientSettings.builder().jwkSetUrl(this.url).build());
        for (String name : new String[] { "self-client", "self-ec" }) {
            assertEquals(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
                    this.verifier.verify(client, ClientCertificateTestSupport.certificate(name)));
        }
        assertEquals(1, this.requests.get());
        // Self-signed client authentication matches the public key in x5c, not subject or certificate bytes.
        assertEquals(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
                this.verifier.verify(client, ClientCertificateTestSupport.certificate("self-same-dn")));
    }

    @Test
    void requiresX5cAndARegisteredMatchingPublicKey() throws Exception {
        RegisteredClient client = X509ClientCertificateVerifierTest.client(
                ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
                ClientSettings.builder().jwkSetUrl(this.url).build());
        X509Certificate certificate = ClientCertificateTestSupport.certificate("self-client");
        this.jwks.set(new JsonWebKeySet(PublicJsonWebKey.Factory.newPublicJwk(certificate.getPublicKey())).toJson());
        X509ClientCertificateVerifierTest.assertInvalid(() -> this.verifier.verify(client, certificate));
        X509ClientCertificateVerifierTest.assertInvalid(() -> this.verifier.verify(client,
                ClientCertificateTestSupport.certificate("untrusted")));
    }

    @Test
    void rejectsExpiredOrFalselySelfSignedCertificatesBeforeLoadingKeys() throws Exception {
        RegisteredClient client = X509ClientCertificateVerifierTest.client(
                ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
                ClientSettings.builder().jwkSetUrl(this.url).build());
        X509ClientCertificateVerifierTest.assertInvalid(() -> this.verifier.verify(client,
                ClientCertificateTestSupport.certificate("expired")));
        byte[] tampered = ClientCertificateTestSupport.certificate("self-client").getEncoded();
        tampered[tampered.length - 1] ^= 1;
        X509Certificate falseSignature = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(tampered));
        X509ClientCertificateVerifierTest.assertInvalid(() -> this.verifier.verify(client, falseSignature));
        assertEquals(0, this.requests.get());
    }

    @Test
    void rejectsMissingAndMalformedClientSettingsAndRemoteJwks() throws Exception {
        for (ClientSettings settings : new ClientSettings[] { ClientSettings.builder().build(),
                ClientSettings.builder().jwkSetUrl("file:/tmp/keys").build() }) {
            var client = X509ClientCertificateVerifierTest.client(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
                    settings);
            X509ClientCertificateVerifierTest.assertInvalid(() -> this.verifier.verify(client,
                    ClientCertificateTestSupport.certificate("self-client")));
        }
        this.jwks.set("not json");
        var client = X509ClientCertificateVerifierTest.client(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
                ClientSettings.builder().jwkSetUrl(this.url).build());
        X509ClientCertificateVerifierTest.assertInvalid(() -> this.verifier.verify(client,
                ClientCertificateTestSupport.certificate("self-client")));
        for (ClientSettings settings : new ClientSettings[] { ClientSettings.builder().build(),
                ClientSettings.builder().x509CertificateSubjectDN("invalid DN").build() }) {
            var pki = X509ClientCertificateVerifierTest.client(ClientAuthenticationMethod.TLS_CLIENT_AUTH, settings);
            X509ClientCertificateVerifierTest.assertInvalid(() -> this.verifier.verify(pki,
                    ClientCertificateTestSupport.certificate("ca-client")));
        }
    }

    private static RegisteredClient client(ClientAuthenticationMethod method, ClientSettings settings) {
        return RegisteredClient.withId("test").clientId("test").clientAuthenticationMethod(method)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).clientSettings(settings).build();
    }

    private static void assertInvalid(org.junit.jupiter.api.function.Executable action) {
        assertEquals("invalid_client", assertThrows(OAuth2AuthenticationException.class, action).getError().getErrorCode());
    }
}
