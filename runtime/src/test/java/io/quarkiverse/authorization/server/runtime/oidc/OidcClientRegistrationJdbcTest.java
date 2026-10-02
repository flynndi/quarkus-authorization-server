package io.quarkiverse.authorization.server.runtime.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.jose.jws.MacAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.runtime.client.BcryptClientSecretVerifier;
import io.quarkiverse.authorization.server.runtime.jdbc.JdbcTestSupport;
import io.quarkiverse.authorization.server.runtime.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import io.quarkiverse.authorization.server.runtime.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkus.elytron.security.common.BcryptUtil;

class OidcClientRegistrationJdbcTest {

    private JdbcDataSource dataSource;
    private JdbcRegisteredClientRepository repository;
    private final OidcClientRegistrationRegisteredClientConverter toClient = new OidcClientRegistrationRegisteredClientConverter(
            List.of(SignatureAlgorithm.RS256, SignatureAlgorithm.ES256),
            settings -> {
            },
            settings -> {
            });
    private final RegisteredClientOidcClientRegistrationConverter toRegistration = new RegisteredClientOidcClientRegistrationConverter();

    @ParameterizedTest
    @ValueSource(strings = { "tls_client_auth", "self_signed_tls_client_auth" })
    void certificateRegistrationSurvivesJdbcReloadWithoutCreatingASecret(String method) {
        var request = OidcClientRegistrationJdbcTest.request().tokenEndpointAuthenticationMethod(method);
        if ("tls_client_auth".equals(method))
            request.tlsClientAuthSubjectDn("CN=client,O=Example");
        else
            request.jwkSetUrl("https://client.example/certificates");
        RegisteredClient client = this.toClient.convert(request.build());
        this.repository.save(client);
        var reloaded = new JdbcRegisteredClientRepository(this.dataSource).findByClientId(client.getClientId());
        assertNull(reloaded.getClientSecret());
        assertEquals(client.getClientSettings().getSettings(), reloaded.getClientSettings().getSettings());
        var response = this.toRegistration.map(reloaded);
        assertEquals(method, response.getTokenEndpointAuthenticationMethod());
        assertEquals(client.getClientSettings().getX509CertificateSubjectDN(), response.getTlsClientAuthSubjectDn());
        assertEquals(client.getClientSettings().getJwkSetUrl(),
                response.getJwkSetUrl() == null ? null : response.getJwkSetUrl().toString());
    }

    @BeforeEach
    void setUp() {
        this.dataSource = new JdbcDataSource();
        this.dataSource.setURL(
                "jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE");
        JdbcTestSupport.executeSchema(
                this.dataSource, JdbcRegisteredClientRepository.SCHEMA_LOCATION);
        this.repository = new JdbcRegisteredClientRepository(this.dataSource);
    }

    @ParameterizedTest
    @ValueSource(strings = { "client_secret_basic", "client_secret_post" })
    void storesEncodedSecretAndRoundTripsClientAndTokenSettings(String method) throws Exception {
        RegisteredClient generated = this.toClient.convert(
                request()
                        .clientName("Registered RP")
                        .tokenEndpointAuthenticationMethod(method)
                        .grantType("authorization_code")
                        .grantType("refresh_token")
                        .idTokenSignedResponseAlgorithm("ES256")
                        .build());
        Instant issued = generated.getClientIdIssuedAt().truncatedTo(ChronoUnit.SECONDS);
        Instant expiry = issued.plusSeconds(3600);
        // The registration service encodes a separate persistence copy; conversion and storage
        // do not encode the client secret.
        RegisteredClient stored = RegisteredClient.from(generated)
                .clientIdIssuedAt(issued)
                .clientSecret(BcryptUtil.bcryptHash(generated.getClientSecret(), 4))
                .clientSecretExpiresAt(expiry)
                .tokenSettings(
                        TokenSettings.withSettings(
                                generated.getTokenSettings().getSettings())
                                .refreshTokenTimeToLive(Duration.ofHours(2))
                                .reuseRefreshTokens(false)
                                .build())
                .build();
        this.repository.save(stored);
        var restored = new JdbcRegisteredClientRepository(this.dataSource)
                .findByClientId(stored.getClientId());
        assertEquals(stored, restored);
        assertTrue(
                new BcryptClientSecretVerifier()
                        .matches(generated.getClientSecret(), restored.getClientSecret()));
        try (var connection = this.dataSource.getConnection();
                var statement = connection.prepareStatement(
                        "select client_secret, client_settings, token_settings from"
                                + " oauth2_registered_client where id = ?")) {
            statement.setString(1, stored.getId());
            try (var rows = statement.executeQuery()) {
                assertTrue(rows.next());
                assertFalse(rows.getString(1).contains(generated.getClientSecret()));
                assertTrue(rows.getString(2).contains("requireProofKey"));
                assertTrue(rows.getString(3).contains("ES256"));
            }
        }
        var response = this.toRegistration.map(restored);
        assertEquals(expiry, response.getClientSecretExpiresAt());
        assertEquals("ES256", response.getIdTokenSignedResponseAlgorithm());
        assertEquals(List.of("https://rp.example/bye"), response.getPostLogoutRedirectUris());
        assertTrue(restored.getClientSettings().isRequireProofKey());
        assertTrue(restored.getClientSettings().isRequireAuthorizationConsent());
        assertFalse(restored.getTokenSettings().isReuseRefreshTokens());
    }

    @Test
    void publicRegistrationHasNoSecretAfterJdbcReplay() {
        var generated = this.toClient.convert(request().tokenEndpointAuthenticationMethod("none").build());
        this.repository.save(generated);
        var restored = new JdbcRegisteredClientRepository(this.dataSource).findById(generated.getId());
        assertNull(restored.getClientSecret());
        assertNull(restored.getClientSecretExpiresAt());
        assertEquals(generated.getClientSettings(), restored.getClientSettings());
        var response = this.toRegistration.map(restored);
        assertEquals("none", response.getTokenEndpointAuthenticationMethod());
        assertNull(response.getClientSecret());
        assertNull(response.getRegistrationAccessToken());
    }

    @ParameterizedTest
    @ValueSource(strings = { "private_key_jwt", "client_secret_jwt" })
    void persistsJwtAuthenticationMethodAlgorithmAndKeyMaterial(String method) {
        var request = OidcClientRegistrationJdbcTest.request().tokenEndpointAuthenticationMethod(method);
        if ("private_key_jwt".equals(method)) {
            request.jwkSetUrl("https://client.example/jwks").tokenEndpointAuthenticationSigningAlgorithm("ES256");
        } else {
            request.tokenEndpointAuthenticationSigningAlgorithm("HS512");
        }
        var generated = this.toClient.convert(request.build());
        // Keep this metadata round-trip test within the schema's timestamp precision.
        var client = RegisteredClient.from(generated)
                .clientIdIssuedAt(generated.getClientIdIssuedAt().truncatedTo(ChronoUnit.MICROS))
                .build();
        this.repository.save(client);
        var restored = new JdbcRegisteredClientRepository(this.dataSource).findByClientId(client.getClientId());
        assertEquals(client, restored);
        assertTrue(restored.getClientAuthenticationMethods().contains(new ClientAuthenticationMethod(method)));
        if ("private_key_jwt".equals(method)) {
            assertNull(restored.getClientSecret());
            assertEquals("https://client.example/jwks", restored.getClientSettings().getJwkSetUrl());
            assertEquals(SignatureAlgorithm.ES256,
                    restored.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm());
        } else {
            assertEquals(client.getClientSecret(), restored.getClientSecret());
            assertEquals(MacAlgorithm.HS512, restored.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm());
        }
        assertEquals(method, this.toRegistration.map(restored).getTokenEndpointAuthenticationMethod());
    }

    @Test
    void updateClearsSecretExpiryAndPreservesLogoutAndSigningSettings() {
        var generated = this.toClient.convert(request().build());
        var client = RegisteredClient.from(generated)
                .clientSecret(BcryptUtil.bcryptHash(generated.getClientSecret(), 4))
                .clientSecretExpiresAt(Instant.now().plusSeconds(600))
                .build();
        this.repository.save(client);
        this.repository.save(
                RegisteredClient.from(client)
                        .clientSecretExpiresAt(null)
                        .postLogoutRedirectUris(values -> values.clear())
                        .postLogoutRedirectUri("https://rp.example/new")
                        .tokenSettings(
                                TokenSettings.withSettings(client.getTokenSettings().getSettings())
                                        .idTokenSignatureAlgorithm(SignatureAlgorithm.ES256)
                                        .build())
                        .build());
        var response = this.toRegistration.map(
                new JdbcRegisteredClientRepository(this.dataSource)
                        .findById(client.getId()));
        assertNull(response.getClientSecretExpiresAt());
        assertEquals(List.of("https://rp.example/new"), response.getPostLogoutRedirectUris());
        assertEquals("ES256", response.getIdTokenSignedResponseAlgorithm());
    }

    private static OidcClientRegistration.Builder request() {
        return OidcClientRegistration.builder()
                .redirectUri("https://rp.example/callback")
                .postLogoutRedirectUri("https://rp.example/bye")
                .scope("openid")
                .scope("profile");
    }
}
