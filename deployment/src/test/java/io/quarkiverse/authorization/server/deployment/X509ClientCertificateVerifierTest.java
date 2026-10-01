package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.runtime.client.authentication.ClientJwkSetCache;
import io.quarkiverse.authorization.server.runtime.client.authentication.ClientJwkSetUrlPolicy;
import io.quarkiverse.authorization.server.runtime.client.authentication.X509ClientCertificateVerifier;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.PemTrustOptions;
import io.vertx.core.net.PfxOptions;

class X509ClientCertificateVerifierTest {
    private Vertx vertx;
    private X509ClientCertificateVerifier verifier;
    private final AtomicReference<String> jwks = new AtomicReference<>();
    private final AtomicInteger requests = new AtomicInteger();
    private io.vertx.core.http.HttpServer server;
    private String url;

    @BeforeEach
    void startJwks() throws Exception {
        this.jwks.set(ClientCertificateTestSupport.jwks("self-client", "self-ec"));
        this.vertx = Vertx.vertx();
        this.server = this.vertx.createHttpServer(new HttpServerOptions().setSsl(true)
                .setPfxKeyCertOptions(new PfxOptions().setPath("mtls/server.p12").setPassword("password")))
                .requestHandler(request -> {
                    this.requests.incrementAndGet();
                    request.response().putHeader("Content-Type", "application/json")
                            .putHeader("Cache-Control", "max-age=300").end(this.jwks.get());
                }).listen(0, "127.0.0.1").toCompletionStage().toCompletableFuture()
                .get(5, TimeUnit.SECONDS);
        String origin = "https://localhost:" + this.server.actualPort();
        this.url = origin + "/jwks";
        var http = this.vertx.createHttpClient(new HttpClientOptions()
                .setTrustOptions(new PemTrustOptions().addCertPath("mtls/ca.pem")));
        this.verifier = new X509ClientCertificateVerifier(new ClientJwkSetCache(http,
                new ClientJwkSetUrlPolicy(
                        Set.of(origin))));
    }

    @AfterEach
    void stopJwks() throws Exception {
        if (this.vertx != null)
            this.vertx.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
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
