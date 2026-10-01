package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.runtime.client.authentication.JwtClientAssertionAuthenticationRequest;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import io.restassured.http.ContentType;
import io.restassured.specification.RequestSpecification;

class X509ClientAuthenticationTest {
    private static final String ISSUER = "https://localhost:8444/api";
    private static final String TOKEN = "/certificate/token";
    private static final String SECRET = "0123456789abcdef".repeat(4);

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest().withApplicationRoot(jar -> {
        jar.addClasses(ClientCertificateTestSupport.class, ClientCertificateTestSupport.JwksResource.class,
                ClientAssertionTestSupport.class, RegistrationScopePolicy.class);
        for (String resource : List.of("server.p12", "ca.pem", "truststore.p12", "ca-client.p12", "ca-leaf-only.p12",
                "wrong-client.p12",
                "self-client.p12", "self-ec.p12", "untrusted.p12", "self-same-dn.p12", "self-client.pem", "self-ec.pem")) {
            jar.addAsResource("mtls/" + resource);
        }
        jar.addAsResource(
                new StringAsset(
                        """
                                quarkus.http.root-path=/api
                                quarkus.tls.jwks.trust-store.pem.certs=mtls/ca.pem
                                quarkus.authorization-server.client-jwks.tls-configuration-name=jwks
                                quarkus.authorization-server.client-jwks.allowed-private-origins=https://localhost:8444
                                quarkus.http.ssl.client-auth=request
                                quarkus.http.ssl.certificate.key-store-file=mtls/server.p12
                                quarkus.http.ssl.certificate.key-store-password=password
                                quarkus.http.ssl.certificate.trust-store-file=mtls/truststore.p12
                                quarkus.http.ssl.certificate.trust-store-password=password
                                quarkus.authorization-server.issuer=https://localhost:8444/api
                                quarkus.authorization-server.token-endpoint=/certificate/token
                                quarkus.authorization-server.oidc.enabled=true
                                quarkus.authorization-server.pushed-authorization-requests-enabled=true
                                quarkus.authorization-server.oidc.client-registration.enabled=true
                                quarkus.authorization-server.oidc-client-registration-endpoint=/clients
                                quarkus.authorization-server.clients.pki.client-authentication-methods=tls_client_auth
                                quarkus.authorization-server.clients.pki.x509-certificate-subject-dn=O=OAuth Test, CN=ca-client
                                quarkus.authorization-server.clients.pki.authorization-grant-types=client_credentials,urn:ietf:params:oauth:grant-type:device_code,authorization_code
                                quarkus.authorization-server.clients.pki.redirect-uris=https://client.example/callback
                                quarkus.authorization-server.clients.pki.scopes=message.read
                                quarkus.authorization-server.clients.self.client-authentication-methods=self_signed_tls_client_auth
                                quarkus.authorization-server.clients.self.jwk-set-url=https://localhost:8444/api/fixture/jwks
                                quarkus.authorization-server.clients.self.authorization-grant-types=client_credentials,urn:ietf:params:oauth:grant-type:device_code,authorization_code
                                quarkus.authorization-server.clients.self.redirect-uris=https://client.example/callback
                                quarkus.authorization-server.clients.self.scopes=message.read
                                quarkus.authorization-server.clients.basic.client-authentication-methods=client_secret_basic,client_secret_post
                                quarkus.authorization-server.clients.basic.client-secret=%s
                                quarkus.authorization-server.clients.basic.authorization-grant-types=client_credentials
                                quarkus.authorization-server.clients.basic.scopes=message.read
                                quarkus.authorization-server.clients.jwt.client-authentication-methods=client_secret_jwt
                                quarkus.authorization-server.clients.jwt.client-secret=%s
                                quarkus.authorization-server.clients.jwt.token-endpoint-authentication-signing-algorithm=HS256
                                quarkus.authorization-server.clients.jwt.authorization-grant-types=client_credentials
                                """
                                .formatted(io.quarkus.elytron.security.common.BcryptUtil.bcryptHash(SECRET, 4), SECRET)),
                "application.properties");
    });

    @Inject
    OAuth2AuthorizationService service;
    @Inject
    RegisteredClientRepository clients;

    @ParameterizedTest
    @CsvSource({ "pki,ca-client", "pki,ca-leaf-only", "self,self-client", "self,self-ec" })
    void authenticatesOverTlsAtAllFiveEndpoints(String client, String certificate) throws Exception {
        String token = X509ClientAuthenticationTest.request(certificate).formParam("client_id", client)
                .formParam("grant_type", "client_credentials").formParam("scope", "message.read").post(TOKEN)
                .then().statusCode(200).body("token_type", equalTo("Bearer")).extract().path("access_token");
        X509ClientAuthenticationTest.request(certificate).formParam("client_id", client).formParam("token", token)
                .post("/oauth2/introspect").then().statusCode(200).body("active", equalTo(true))
                .body("client_id", equalTo(client)).body("$", not(hasKey("cnf")));
        X509ClientAuthenticationTest.request(certificate).formParam("client_id", client).formParam("token", token)
                .post("/oauth2/revoke").then().statusCode(200);
        X509ClientAuthenticationTest.request(certificate).formParam("client_id", client).formParam("token", token)
                .post("/oauth2/introspect").then().statusCode(200).body("active", equalTo(false));
        X509ClientAuthenticationTest.request(certificate).formParam("client_id", client)
                .formParam("scope", "message.read").post("/oauth2/device_authorization")
                .then().statusCode(200).body("device_code", notNullValue());
        X509ClientAuthenticationTest.request(certificate).formParam("client_id", client).formParam("response_type", "code")
                .formParam("redirect_uri", "https://client.example/callback").formParam("scope", "message.read")
                .formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .formParam("code_challenge_method", "S256")
                .post("/oauth2/par").then().statusCode(201).body("request_uri", notNullValue());
    }

    @ParameterizedTest
    @CsvSource({ "pki,wrong-client", "pki,self-same-dn", "self,ca-client", "basic,ca-client", "unknown,ca-client",
            "pki,self-client" })
    void rejectsMismatchedCertificateOrUnregisteredMethod(String client, String certificate) throws Exception {
        X509ClientAuthenticationTest.request(certificate).formParam("client_id", client)
                .formParam("grant_type", "client_credentials").post(TOKEN).then().statusCode(401)
                .body("error", equalTo("invalid_client"));
    }

    @Test
    void absentCertificateAndForwardedCertificateHeadersCannotAuthenticate() throws Exception {
        for (String client : List.of("pki", "self")) {
            X509ClientAuthenticationTest.request(null).formParam("client_id", client)
                    .formParam("grant_type", "client_credentials").post(TOKEN).then().statusCode(401)
                    .body("error", equalTo("invalid_client"));
            given().contentType(ContentType.URLENC).header("X-Forwarded-Client-Cert", "CN=ca-client,O=OAuth Test")
                    .formParam("client_id", client).formParam("grant_type", "client_credentials")
                    .post(TOKEN).then().statusCode(401).body("error", equalTo("invalid_client"));
        }
    }

    @Test
    void requiresUniqueNonblankClientId() throws Exception {
        for (List<String> values : List.of(List.<String> of(), List.of(" "), List.of("pki", "pki"))) {
            var request = X509ClientAuthenticationTest.request("ca-client").formParam("grant_type", "client_credentials");
            if (!values.isEmpty())
                request.formParam("client_id", values);
            request.post(TOKEN).then().statusCode(400).body("error", equalTo("invalid_request"));
        }
    }

    @Test
    void explicitBasicPostAndJwtCredentialsCanCoexistWithTlsAndStillRequireTheirOwnCredentials() throws Exception {
        for (String certificate : new String[] { null, "ca-client" }) {
            X509ClientAuthenticationTest.request(certificate).auth().preemptive().basic("basic", SECRET)
                    .formParam("grant_type", "client_credentials").post(TOKEN).then().statusCode(200);
            X509ClientAuthenticationTest.request(certificate).formParam("client_id", "basic").formParam("client_secret", SECRET)
                    .formParam("grant_type", "client_credentials").post(TOKEN).then().statusCode(200);
            X509ClientAuthenticationTest.request(certificate).formParam("client_id", "jwt")
                    .formParam("client_assertion_type", JwtClientAssertionAuthenticationRequest.ASSERTION_TYPE)
                    .formParam("client_assertion", ClientAssertionTestSupport.assertion("jwt", SECRET, ISSUER, null))
                    .formParam("grant_type", "client_credentials").post(TOKEN).then().statusCode(200);
        }
        X509ClientAuthenticationTest.request("ca-client").auth().preemptive().basic("pki", "wrong")
                .formParam("grant_type", "client_credentials").post(TOKEN).then().statusCode(401);
    }

    @Test
    void publishesCertificateMethodsWhenTlsClientAuthenticationIsConfigured() throws Exception {
        for (String endpoint : List.of("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")) {
            var response = X509ClientAuthenticationTest.request(null).get(endpoint).then().statusCode(200)
                    .body("$", not(hasKey("tls_client_certificate_bound_access_tokens")))
                    .body("$", not(hasKey("mtls_endpoint_aliases")));
            for (String name : List.of("token", "introspection", "revocation")) {
                response.body(name + "_endpoint_auth_methods_supported",
                        hasItems("tls_client_auth", "self_signed_tls_client_auth"));
            }
        }
    }

    @ParameterizedTest
    @CsvSource({ "tls_client_auth,ca-client", "self_signed_tls_client_auth,self-client" })
    void dynamicallyRegistersAuthenticatesAndReadsCertificateClient(String method, String certificate) throws Exception {
        String initial = UUID.randomUUID().toString();
        Set<String> scopes = Set.of("client.create");
        this.service.save(OAuth2Authorization.withRegisteredClient(this.clients.findByClientId("basic"))
                .principalName("basic").authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(scopes).accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, initial,
                        Instant.now(), Instant.now().plusSeconds(300), scopes))
                .build());
        String property = method.equals("tls_client_auth") ? "tls_client_auth_subject_dn" : "jwks_uri";
        String value = method.equals("tls_client_auth") ? "O=OAuth Test,CN=ca-client"
                : "https://localhost:8444/api/fixture/jwks";
        var registration = X509ClientAuthenticationTest.request(null).auth().oauth2(initial).contentType(ContentType.JSON)
                .body(java.util.Map.of("redirect_uris", List.of("https://rp.example/callback"),
                        "grant_types", List.of("client_credentials"), "scope", "message.read",
                        "token_endpoint_auth_method", method, property, value))
                .post("/clients")
                .then().statusCode(201).body("$", not(hasKey("client_secret")))
                .body(property, equalTo(value)).extract().response();
        String clientId = registration.path("client_id");
        X509ClientAuthenticationTest.request(certificate).formParam("client_id", clientId)
                .formParam("grant_type", "client_credentials").post(TOKEN).then().statusCode(200);
        X509ClientAuthenticationTest.request(null).auth().oauth2(registration.path("registration_access_token"))
                .queryParam("client_id", clientId).get("/clients").then().statusCode(200)
                .body(property, equalTo(value)).body("token_endpoint_auth_method", equalTo(method))
                .body("$", not(hasKey("client_secret")));
    }

    @Test
    void untrustedPeerIsRejectedByTheTlsHandshake() throws Exception {
        var store = java.security.KeyStore.getInstance("PKCS12");
        try (var input = java.nio.file.Files.newInputStream(Path.of(X509ClientAuthenticationTest.resource("untrusted")))) {
            store.load(input, "password".toCharArray());
        }
        var factory = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
        factory.init(store, "password".toCharArray());
        var delegate = (javax.net.ssl.X509KeyManager) factory.getKeyManagers()[0];
        // Force presentation despite the server's advertised CA names, so this checks TLS trust rejection.
        javax.net.ssl.X509ExtendedKeyManager forced = new javax.net.ssl.X509ExtendedKeyManager() {
            public String chooseEngineClientAlias(String[] types, java.security.Principal[] issuers,
                    javax.net.ssl.SSLEngine engine) {
                return "untrusted";
            }

            public String[] getClientAliases(String type, java.security.Principal[] issuers) {
                return new String[] { "untrusted" };
            }

            public String chooseClientAlias(String[] types, java.security.Principal[] issuers, java.net.Socket socket) {
                return "untrusted";
            }

            public String[] getServerAliases(String type, java.security.Principal[] issuers) {
                return null;
            }

            public String chooseServerAlias(String type, java.security.Principal[] issuers, java.net.Socket socket) {
                return null;
            }

            public java.security.cert.X509Certificate[] getCertificateChain(String alias) {
                return delegate.getCertificateChain(alias);
            }

            public java.security.PrivateKey getPrivateKey(String alias) {
                return delegate.getPrivateKey(alias);
            }
        };
        var trust = java.security.KeyStore.getInstance("PKCS12");
        try (var input = java.nio.file.Files.newInputStream(Path.of(X509ClientAuthenticationTest.resource("truststore")))) {
            trust.load(input, "password".toCharArray());
        }
        var trustFactory = javax.net.ssl.TrustManagerFactory
                .getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(trust);
        var ssl = javax.net.ssl.SSLContext.getInstance("TLS");
        ssl.init(new javax.net.ssl.KeyManager[] { forced }, trustFactory.getTrustManagers(), null);
        try (var client = java.net.http.HttpClient.newBuilder().sslContext(ssl)
                .version(java.net.http.HttpClient.Version.HTTP_1_1).build()) {
            var request = java.net.http.HttpRequest.newBuilder(java.net.URI.create(ISSUER + TOKEN))
                    .timeout(java.time.Duration.ofSeconds(10)).header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString("client_id=self&grant_type=client_credentials"))
                    .build();
            assertThrows(java.io.IOException.class,
                    () -> client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString()));
        }
    }

    private static RequestSpecification request(String certificate) throws Exception {
        SSLConfig ssl = SSLConfig.sslConfig().trustStore(X509ClientAuthenticationTest.resource("truststore"), "password")
                .trustStoreType("PKCS12");
        if (certificate != null)
            ssl = ssl.keyStore(X509ClientAuthenticationTest.resource(certificate), "password").keystoreType("PKCS12");
        return given().config(RestAssuredConfig.config().sslConfig(ssl)).baseUri("https://localhost").port(8444)
                .contentType(ContentType.URLENC);
    }

    private static String resource(String name) throws Exception {
        return Path.of(X509ClientAuthenticationTest.class.getResource("/mtls/" + name + ".p12").toURI()).toString();
    }
}
