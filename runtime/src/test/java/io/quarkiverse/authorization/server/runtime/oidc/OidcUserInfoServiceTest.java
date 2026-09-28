package io.quarkiverse.authorization.server.runtime.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.h2.jdbcx.JdbcConnectionPool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.OidcUserInfo;
import io.quarkiverse.authorization.server.oidc.userinfo.OidcUserInfoContext;
import io.quarkiverse.authorization.server.runtime.jdbc.JdbcTestSupport;
import io.quarkiverse.authorization.server.runtime.oidc.userinfo.DefaultOidcUserInfoMapper;
import io.quarkiverse.authorization.server.runtime.oidc.userinfo.OidcUserInfoService;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkus.security.credential.TokenCredential;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class OidcUserInfoServiceTest {
    private JdbcConnectionPool dataSource;
    private JdbcOAuth2AuthorizationService service;
    private OidcUserInfoService provider;
    private RegisteredClient client;

    @BeforeEach
    void setUp() {
        this.dataSource = JdbcConnectionPool.create(
                "jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1", "sa", "");
        JdbcTestSupport.executeSchema(
                this.dataSource, JdbcRegisteredClientRepository.SCHEMA_LOCATION);
        JdbcTestSupport.executeSchema(
                this.dataSource, JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
        JdbcRegisteredClientRepository clients = new JdbcRegisteredClientRepository(this.dataSource);
        this.client = RegisteredClient.withId("registration")
                .clientId("client")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .scope("openid")
                .build();
        clients.save(this.client);
        this.service = new JdbcOAuth2AuthorizationService(this.dataSource, clients);
        this.provider = new OidcUserInfoService(this.service, new DefaultOidcUserInfoMapper());
    }

    @AfterEach
    void close() {
        this.dataSource.dispose();
    }

    @Test
    void usesPersistedIdTokenAndCurrentAccessScopesNotAllAuthorizedScopes() {
        this.service.save(authorization(Set.of("openid", "email")).build());
        SecurityIdentity principal = identity("alice", "access");
        var result = this.provider.userInfo(principal);
        assertEquals(
                Map.of(
                        "sub",
                        "id-token-subject",
                        "email",
                        "alice@example.com",
                        "email_verified",
                        true),
                result.getClaims());
        assertEquals(
                Set.of("openid", "profile", "email", "phone", "address", "groups", "perms"),
                this.service.findById("authorization").getAuthorizedScopes());
    }

    @Test
    void mapsStandardAndApplicationScopesButNeverLeaksProtocolOrUnscopedClaims() {
        this.service.save(
                authorization(
                        Set.of(
                                "openid", "profile", "email", "phone", "address", "groups",
                                "perms"))
                        .build());
        var userInfo = this.provider.userInfo(identity("alice", "access"));
        assertEquals("Alice", userInfo.getFullName());
        assertEquals("CN", userInfo.getAddress().getCountry());
        assertEquals("+123", userInfo.getPhoneNumber());
        assertTrue(userInfo.getClaims().containsKey("groups"));
        assertTrue(userInfo.getClaims().containsKey("perms"));
        assertFalse(userInfo.getClaims().containsKey("iss"));
        assertFalse(userInfo.getClaims().containsKey("secret"));
    }

    @Test
    void allowsApplicationMapperAndRequiresItsContext() {
        this.service.save(authorization(Set.of("openid")).build());
        var provider = new OidcUserInfoService(
                this.service,
                context -> {
                    assertEquals("authorization", context.authorization().getId());
                    assertEquals(Set.of("openid"), context.accessToken().getScopes());
                    return OidcUserInfo.builder()
                            .subject(
                                    context.authorization()
                                            .getToken(OidcIdToken.class)
                                            .getToken()
                                            .getSubject())
                            .claim("custom", true)
                            .build();
                });
        assertTrue(provider.userInfo(identity("alice", "access")).getClaimAsBoolean("custom"));
        assertThrows(NullPointerException.class, () -> new OidcUserInfoService(this.service, null));
        assertThrows(
                NullPointerException.class,
                () -> new OidcUserInfoContext(identity("alice", "access"), null, null));
    }

    @Test
    void rejectsUnknownWrongTypeExpiredInvalidatedAndMismatchedIdentity() {
        this.service.save(authorization(Set.of("openid")).build());
        for (String token : new String[] { "unknown", "id", "refresh" }) {
            assertError("invalid_token", identity("alice", token));
        }
        assertError("invalid_token", identity("mallory", "access"));
        assertError(
                "invalid_token",
                QuarkusSecurityIdentity.builder()
                        .setPrincipal(new QuarkusPrincipal("alice"))
                        .build());
        Instant now = Instant.now();
        this.service.save(
                authorization(Set.of("openid"))
                        .accessToken(
                                new OAuth2AccessToken(
                                        OAuth2AccessToken.TokenType.BEARER,
                                        "access",
                                        now.minusSeconds(3600),
                                        now.minusSeconds(1),
                                        Set.of("openid")))
                        .build());
        assertError("invalid_token", identity("alice", "access"));
        this.service.save(
                authorization(Set.of("openid"))
                        .token(
                                new OAuth2AccessToken(
                                        OAuth2AccessToken.TokenType.BEARER,
                                        "access",
                                        now,
                                        now.plusSeconds(300),
                                        Set.of("openid")),
                                metadata -> metadata.put(
                                        OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                        true))
                        .build());
        assertError("invalid_token", identity("alice", "access"));
    }

    @Test
    void rejectsMissingOpenidAndMissingIdTokenButDoesNotRequireUnexpiredIdToken() {
        this.service.save(authorization(Set.of("email")).build());
        assertError("insufficient_scope", identity("alice", "access"));
        Instant now = Instant.now();
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(this.client)
                .id("authorization")
                .principalName("alice")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .accessToken(
                        new OAuth2AccessToken(
                                OAuth2AccessToken.TokenType.BEARER,
                                "access",
                                now,
                                now.plusSeconds(300),
                                Set.of("openid")))
                .build();
        this.service.save(authorization);
        assertError("invalid_token", identity("alice", "access"));
        OidcIdToken expired = new OidcIdToken(
                "expired-id",
                now.minusSeconds(3600),
                now.minusSeconds(1800),
                Map.of("sub", "alice"));
        this.service.save(
                OAuth2Authorization.from(authorization)
                        .token(
                                expired,
                                metadata -> metadata.put(
                                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                        expired.getClaims()))
                        .build());
        assertEquals("alice", this.provider.userInfo(identity("alice", "access")).getSubject());
    }

    private void assertError(String code, SecurityIdentity identity) {
        var error = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.provider.userInfo(identity));
        assertEquals(code, error.getError().getErrorCode());
    }

    @Test
    void dpopIdentityRequiresVerifiedProofAndMatchingPersistedBinding() {
        Instant now = Instant.now();
        var token = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.DPOP,
                "access",
                now,
                now.plusSeconds(300),
                Set.of("openid", "email"));
        this.service.save(
                authorization(token.getScopes())
                        .token(
                                token,
                                metadata -> metadata.put(
                                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                        Map.of("cnf", Map.of("jkt", "a".repeat(43)))))
                        .build());
        assertError("invalid_token", identity("alice", "access"));
        var unidentifiedProof = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("alice"))
                .addCredential(new TokenCredential("access", "dpop"))
                .build();
        assertError("invalid_token", unidentifiedProof);
        assertError(
                "invalid_token",
                QuarkusSecurityIdentity.builder(unidentifiedProof)
                        .addAttribute(
                                DPoPProof.class.getName(),
                                new DPoPProof("b".repeat(43), "proof", now.plusSeconds(60)))
                        .build());
        var principal = QuarkusSecurityIdentity.builder(unidentifiedProof)
                .addAttribute(
                        DPoPProof.class.getName(),
                        new DPoPProof("a".repeat(43), "proof", now.plusSeconds(60)))
                .build();
        assertEquals("alice@example.com", this.provider.userInfo(principal).getEmail());
        // A second service call rechecks authorization, without consuming the authenticated proof.
        assertEquals("id-token-subject", this.provider.userInfo(principal).getSubject());
        this.service.save(
                authorization(token.getScopes())
                        .token(
                                token,
                                metadata -> {
                                    metadata.put(
                                            OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                            Map.of("cnf", Map.of("jkt", "a".repeat(43))));
                                    metadata.put(
                                            OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                            true);
                                })
                        .build());
        assertError("invalid_token", principal);
    }

    @Test
    void rejectsInconsistentTypeOrMissingConfirmationEvenWithDpopIdentity() {
        var principal = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("alice"))
                .addCredential(new TokenCredential("access", "dpop"))
                .addAttribute(
                        DPoPProof.class.getName(),
                        new DPoPProof(
                                "a".repeat(43), "proof", Instant.now().plusSeconds(60)))
                .build();
        for (var type : List.of(OAuth2AccessToken.TokenType.BEARER, OAuth2AccessToken.TokenType.DPOP)) {
            for (var claims : List.<Map<String, Object>> of(
                    Map.of(),
                    Map.of("cnf", Map.of()),
                    Map.of("cnf", Map.of("jkt", "invalid")))) {
                Instant now = Instant.now();
                this.service.save(
                        authorization(Set.of("openid"))
                                .token(
                                        new OAuth2AccessToken(
                                                type,
                                                "access",
                                                now,
                                                now.plusSeconds(300),
                                                Set.of("openid")),
                                        metadata -> metadata.put(
                                                OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                                claims))
                                .build());
                assertError("invalid_token", principal);
            }
        }
    }

    private OAuth2Authorization.Builder authorization(Set<String> accessScopes) {
        Instant now = Instant.now();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "id-token-subject");
        claims.put("name", "Alice");
        claims.put("email", "alice@example.com");
        claims.put("email_verified", true);
        claims.put("phone_number", "+123");
        claims.put("address", Map.of("country", "CN", "locality", "Shanghai"));
        claims.put("nested_claim", Map.of("key", "value"));
        claims.put("groups", List.of("user"));
        claims.put("perms", List.of("read"));
        claims.put("iss", "https://issuer.example");
        claims.put("secret", "not-for-userinfo");
        OidcIdToken id = new OidcIdToken("id", now, now.plusSeconds(1800), claims);
        return OAuth2Authorization.withRegisteredClient(this.client)
                .id("authorization")
                .principalName("alice")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizedScopes(
                        Set.of("openid", "profile", "email", "phone", "address", "groups", "perms"))
                .accessToken(
                        new OAuth2AccessToken(
                                OAuth2AccessToken.TokenType.BEARER,
                                "access",
                                now,
                                now.plusSeconds(300),
                                accessScopes))
                .refreshToken(new OAuth2RefreshToken("refresh", now, now.plusSeconds(3600)))
                .token(
                        id,
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                id.getClaims()));
    }

    private static SecurityIdentity identity(String name, String token) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(name))
                .addCredential(new TokenCredential(token, "bearer"))
                .build();
    }
}
