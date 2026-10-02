package io.quarkiverse.authorization.server.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.node.BigIntegerNode;
import com.fasterxml.jackson.databind.node.DecimalNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.POJONode;
import com.fasterxml.jackson.databind.node.TextNode;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.jose.jws.MacAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTokenBinding;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.token.OAuth2TokenExchangeTokenCustomizers;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.StringPermission;
import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

class JdbcJsonCodecTest {

    private static final String ACTORS = OAuth2TokenExchangeTokenCustomizers.ACTORS_ATTRIBUTE;
    private static final Instant AUTHENTICATED_AT = Instant.parse("2030-01-01T00:00:00.123456789Z");
    private final JdbcJsonCodec codec = new JdbcJsonCodec();
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void readsSettingsFixturesAndWritesTheSameStableFormat() throws Exception {
        ClientSettings client = this.codec.readClientSettings(JdbcJsonCodecTest.fixture("client-settings"));
        assertTrue(client.isRequireProofKey());
        assertFalse(client.isRequireAuthorizationConsent());
        assertEquals("https://client.example/jwks", client.getJwkSetUrl());
        assertEquals(SignatureAlgorithm.RS256, client.getTokenEndpointAuthenticationSigningAlgorithm());
        assertEquals("CN=client", client.getX509CertificateSubjectDN());
        assertEquals(this.json.readTree(JdbcJsonCodecTest.fixture("client-settings")),
                this.json.readTree(new JdbcJsonCodec().writeClientSettings(client)));

        TokenSettings token = this.codec.readTokenSettings(JdbcJsonCodecTest.fixture("token-settings"));
        assertEquals(TokenSettings.builder().build().getSettings(), token.getSettings());
        assertEquals(this.json.readTree(JdbcJsonCodecTest.fixture("token-settings")),
                this.json.readTree(new JdbcJsonCodec().writeTokenSettings(token)));
    }

    @Test
    void missingOptionalSettingsUseDomainDefaultsWithoutAFormatVersion() {
        String clientJson = "{\"kind\":\"client-settings\",\"data\":{\"extensions\":{}}}";
        String tokenJson = "{\"kind\":\"token-settings\",\"data\":{\"extensions\":{}}}";
        assertEquals(ClientSettings.builder().build().getSettings(), this.codec.readClientSettings(clientJson).getSettings());
        assertEquals(TokenSettings.builder().build().getSettings(), this.codec.readTokenSettings(tokenJson).getSettings());
        assertFalse(this.codec.writeTokenSettings(TokenSettings.builder().build()).contains("formatVersion"));
    }

    @Test
    void readsAuthorizationFixtureAndRestoresProtocolObjects() throws Exception {
        Map<String, Object> attributes = this.codec.readAuthorizationAttributes("alice",
                JdbcJsonCodecTest.fixture("authorization-attributes"));
        SecurityIdentity identity = (SecurityIdentity) attributes.get(SecurityIdentity.class.getName());
        assertEquals("alice", identity.getPrincipal().getName());
        assertEquals(Set.of("reader"), identity.getRoles());
        assertEquals(List.of(Map.of("sub", "actor", "iss", "https://actor.example")), identity.getAttribute(ACTORS));
        assertEquals(new SessionInformation("alice", "session-1", AUTHENTICATED_AT),
                attributes.get(SessionInformation.class.getName()));
        Instant expiry = assertInstanceOf(Instant.class,
                attributes.get(OAuth2AuthorizationRequest.PUSHED_REQUEST_EXPIRES_AT_ATTRIBUTE_NAME));
        assertEquals(AUTHENTICATED_AT.plusSeconds(300), expiry);
        OAuth2AuthorizationRequest request = (OAuth2AuthorizationRequest) attributes
                .get(OAuth2AuthorizationRequest.class.getName());
        assertEquals("https://issuer.example/oauth2/authorize?original=query", request.getAuthorizationRequestUri());
        assertEquals(Set.of("openid", "read"), request.getScopes());
        assertEquals("challenge", request.getAdditionalParameters().get("code_challenge"));
        assertEquals("request-1", request.getAttribute("request-id"));
        assertEquals("request-state", request.getState());
        assertEquals("consent-state", attributes.get("state"));
        String stored = new JdbcJsonCodec().writeAuthorizationAttributes("alice", attributes);
        assertEquals(this.json.readTree(JdbcJsonCodecTest.fixture("authorization-attributes")), this.json.readTree(stored));
        assertFalse(stored.contains("@class"));
        assertFalse(stored.contains("io.quarkus"));
        assertFalse(stored.contains("io.quarkiverse"));
        assertFalse(stored.contains("java.util"));
        assertThrows(UnsupportedOperationException.class, () -> attributes.put("x", "y"));
    }

    @Test
    void fixtureRestoresNbfAsInstantAndKeepsTokenInactive() throws Exception {
        Map<String, Object> metadata = this.codec.readTokenMetadata(JdbcJsonCodecTest.fixture("token-metadata"));
        RegisteredClient client = RegisteredClient.withId("id").clientId("client")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();
        OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access",
                Instant.parse("2020-01-01T00:00:00Z"), Instant.parse("3000-01-01T00:00:00Z"), Set.of("read"));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client).principalName("alice")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .token(token, target -> target.putAll(metadata)).build();
        assertTrue(authorization.getAccessToken().isBeforeUse());
        assertFalse(authorization.getAccessToken().isActive());
        assertInstanceOf(Long.class, authorization.getAccessToken().getClaims().get("auth_time"));
        assertEquals(OAuth2TokenFormat.SELF_CONTAINED.getValue(), metadata.get(OAuth2TokenFormat.class.getName()));
        String stored = this.codec.writeTokenMetadata(metadata);
        assertFalse(stored.contains("io.quarkiverse"));
        assertEquals(this.json.readTree(JdbcJsonCodecTest.fixture("token-metadata")),
                this.json.readTree(stored));
    }

    @Test
    void dpopRefreshMetadataUsesAStableFieldInsteadOfTheRuntimeClassName() throws Exception {
        Map<String, Object> metadata = Map.of(
                OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false,
                DPoPTokenBinding.REFRESH_JKT_METADATA, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        String stored = this.codec.writeTokenMetadata(metadata);
        JsonNode document = this.json.readTree(stored);
        String fixture = JdbcJsonCodecTest.fixture("dpop-refresh-token-metadata");
        assertEquals(this.json.readTree(fixture), document);
        assertFalse(document.path("data").path("extensions").has(DPoPTokenBinding.REFRESH_JKT_METADATA));
        assertFalse(stored.contains(DPoPTokenBinding.class.getName()));
        assertEquals(metadata, new JdbcJsonCodec().readTokenMetadata(fixture));
    }

    @Test
    void identityUsesInterfaceSnapshotAndNeverPersistsAuthenticationCapabilities() {
        SecurityIdentity original = QuarkusSecurityIdentity.builder().setPrincipal(() -> "alice").addRole("reader")
                .addCredential(new PasswordCredential("password-secret".toCharArray()))
                .addAttribute("request", new Object()).addPermissionChecker(permission -> Uni.createFrom().item(true)).build();
        // Exercise an implementation other than QuarkusSecurityIdentity without adding a persistence subtype.
        SecurityIdentity decorated = (SecurityIdentity) java.lang.reflect.Proxy.newProxyInstance(
                SecurityIdentity.class.getClassLoader(), new Class<?>[] { SecurityIdentity.class },
                (proxy, method, arguments) -> method.invoke(original, arguments));
        String stored = this.codec.writeAuthorizationAttributes("alice", Map.of(SecurityIdentity.class.getName(), decorated));
        SecurityIdentity restored = (SecurityIdentity) this.codec.readAuthorizationAttributes("alice", stored)
                .get(SecurityIdentity.class.getName());
        assertInstanceOf(QuarkusSecurityIdentity.class, restored);
        assertEquals("alice", restored.getPrincipal().getName());
        assertEquals(Set.of("reader"), restored.getRoles());
        assertTrue(restored.getCredentials().isEmpty());
        assertTrue(restored.getAttributes().isEmpty());
        assertFalse(restored.checkPermission(new StringPermission("write")).await().indefinitely());
        assertFalse(stored.contains("password-secret"));
        assertFalse(stored.contains("request"));
        assertNotNull(original.getCredential(PasswordCredential.class));
        assertThrows(IllegalArgumentException.class, () -> this.codec.readAuthorizationAttributes("bob", stored));
        assertThrows(IllegalArgumentException.class,
                () -> this.codec.writeAuthorizationAttributes("bob", Map.of(SecurityIdentity.class.getName(), decorated)));
    }

    @Test
    void nestedValuesPreservePrecisionTypesAndCollectionSemantics() {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("byte", (byte) 1);
        values.put("short", (short) 2);
        values.put("integer", 3);
        values.put("long", 3L);
        values.put("bigInteger", new BigInteger("1234567890123456789012345678901234567890"));
        values.put("decimal", new BigDecimal("12345678901234567890.1234567890123456789000"));
        values.put("double", -0.0d);
        values.put("float", -0.0f);
        values.put("instant", AUTHENTICATED_AT);
        values.put("duration", Duration.ofSeconds(30, 123456789));
        values.put("list", Collections.unmodifiableList(Arrays.asList("read", null, AUTHENTICATED_AT)));
        values.put("set", new LinkedHashSet<>(List.of("read", "write")));
        values.put("nested", Map.of("type", "instant", "value", "ordinary business fields"));
        values.put("grant", AuthorizationGrantType.TOKEN_EXCHANGE);
        values.put("authentication", ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        values.put("signature", SignatureAlgorithm.PS256);
        values.put("mac", MacAlgorithm.HS256);
        values.put("tokenFormat", OAuth2TokenFormat.REFERENCE);
        values.put("tokenType", OAuth2TokenType.ACCESS_TOKEN);
        values.put("session", new SessionInformation("alice", "nested", AUTHENTICATED_AT));
        values.put("null", null);
        Map<String, Object> restored = this.codec.readAuthorizationAttributes("alice",
                this.codec.writeAuthorizationAttributes("alice", values));
        assertEquals(values, restored);
        values.forEach((key, value) -> {
            if (value instanceof Number) {
                assertEquals(value.getClass(), restored.get(key).getClass(), key);
            }
        });
        assertInstanceOf(Set.class, restored.get("set"));
        assertInstanceOf(List.class, restored.get("list"));
        assertThrows(UnsupportedOperationException.class, () -> ((Set<?>) restored.get("set")).clear());
        assertThrows(UnsupportedOperationException.class, () -> ((List<?>) restored.get("list")).clear());
        assertThrows(UnsupportedOperationException.class, () -> ((Map<?, ?>) restored.get("nested")).clear());
    }

    @Test
    void preservesNullableAuthorizationRequestFieldsAndMacClientAlgorithm() {
        OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://issuer.example/authorize").clientId("client").build();
        Map<String, Object> attributes = this.codec.readAuthorizationAttributes("client",
                this.codec.writeAuthorizationAttributes("client", Map.of(OAuth2AuthorizationRequest.class.getName(), request)));
        OAuth2AuthorizationRequest restored = (OAuth2AuthorizationRequest) attributes
                .get(OAuth2AuthorizationRequest.class.getName());
        assertNull(restored.getState());
        assertNull(restored.getRedirectUri());
        assertEquals(request.getAuthorizationRequestUri(), restored.getAuthorizationRequestUri());
        ClientSettings settings = ClientSettings.builder().tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256)
                .setting("customTimeout", Duration.ofSeconds(15)).build();
        assertEquals(settings.getSettings(),
                this.codec.readClientSettings(this.codec.writeClientSettings(settings)).getSettings());
    }

    @ParameterizedTest
    @ValueSource(strings = { "null", "[]", "{}", "{\"@class\":\"java.lang.Runtime\"}",
            "{\"kind\":\"client-settings\",\"data\":{\"extensions\":{}}}",
            "{\"kind\":\"token-metadata\",\"kind\":\"token-metadata\",\"data\":{\"extensions\":{}}}",
            "{\"kind\":\"token-metadata\",\"data\":{\"extensions\":{}}} {}",
            "{\"kind\":\"token-metadata\",\"data\":{\"invalidated\":\"false\",\"extensions\":{}}}",
            "{\"kind\":\"token-metadata\",\"data\":{\"claims\":{\"nbf\":\"2999-01-01T00:00:00Z\"},\"extensions\":{}}}",
            "{\"kind\":\"token-metadata\",\"data\":{\"extensions\":{\"metadata.token.invalidated\":true}}}",
            "{\"kind\":\"token-metadata\",\"data\":{\"extensions\":{\"x\":{\"type\":\"java.lang.Runtime\",\"value\":{}}}}}",
            "{\"kind\":\"token-metadata\",\"data\":{\"extensions\":{\"x\":{\"type\":\"set\",\"value\":[\"a\",\"a\"]}}}}",
            "{\"kind\":\"token-metadata\",\"data\":{\"extensions\":{\"x\":{\"type\":\"instant\",\"value\":\"invalid\"}}}}",
            "{\"kind\":\"token-metadata\",\"data\":{\"extensions\":{\"x\":{\"type\":\"signature-algorithm\",\"value\":\"unknown\"}}}}",
            "{\"kind\":\"token-metadata\",\"data\":{\"extensions\":{\"x\":{\"type\":\"long\",\"value\":\"9223372036854775808\"}}}}" })
    void rejectsMalformedOrAmbiguousDocuments(String document) {
        assertThrows(IllegalArgumentException.class, () -> this.codec.readTokenMetadata(document));
    }

    @ParameterizedTest
    @ValueSource(strings = { "credentials", "number-role", "null-role", "number-name", "anonymous", "invalid-actor",
            "session-subject", "request-type" })
    void rejectsCorruptedProtocolSnapshots(String corruption) throws Exception {
        ObjectNode root = (ObjectNode) this.json.readTree(JdbcJsonCodecTest.fixture("authorization-attributes"));
        ObjectNode identity = (ObjectNode) root.path("data").path("identity");
        switch (corruption) {
            case "credentials" -> identity.put("credentials", "secret");
            case "number-role" -> identity.putArray("roles").add(1);
            case "null-role" -> identity.putArray("roles").addNull();
            case "number-name" -> identity.put("principalName", 1);
            case "anonymous" -> identity.put("anonymous", true);
            case "invalid-actor" -> identity.putArray("actors").addObject().put("iss", "issuer");
            case "session-subject" -> ((ObjectNode) root.path("data").path("session")).put("principalName", "bob");
            case "request-type" -> ((ObjectNode) root.path("data").path("authorizationRequest")).put("responseType", "token");
            default -> throw new AssertionError(corruption);
        }
        assertThrows(IllegalArgumentException.class, () -> this.codec.readAuthorizationAttributes("alice", root.toString()));
    }

    @Test
    void rejectsUnsupportedValuesCyclesAndNonFiniteNumbersBeforeStorage() {
        for (Object value : List.of(new Object(), Double.NaN, Float.POSITIVE_INFINITY, Map.of(1, "not a string key"))) {
            assertThrows(IllegalArgumentException.class,
                    () -> this.codec.writeAuthorizationAttributes("alice", Map.of("unsupported", value)));
        }
        Map<String, Object> cycle = new LinkedHashMap<>();
        cycle.put("self", cycle);
        assertThrows(IllegalArgumentException.class, () -> this.codec.writeAuthorizationAttributes("alice", cycle));
        String nested = "{\"kind\":\"token-metadata\",\"data\":{\"extensions\":{\"nested\":"
                + "[".repeat(100) + "null" + "]".repeat(100) + "}}}";
        assertThrows(IllegalArgumentException.class, () -> this.codec.readTokenMetadata(nested));
        assertThrows(IllegalArgumentException.class, () -> this.codec.writeTokenMetadata(
                Map.of(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, Map.of("nbf", "2999-01-01T00:00:00Z"))));
    }

    @Test
    void customAdaptersUseExplicitStableIdsAndCannotReplaceBuiltIns() {
        JdbcJsonValueAdapter<OrderReference> adapter = new OrderReferenceAdapter();
        JdbcJsonCodec custom = new JdbcJsonCodec(List.of(adapter));
        Map<String, Object> source = Map.of("order", new OrderReference("order-123"));
        String stored = custom.writeAuthorizationAttributes("alice", source);
        assertTrue(stored.contains("custom:order-reference"));
        assertFalse(stored.contains(OrderReference.class.getName()));
        assertEquals(source,
                new JdbcJsonCodec(List.of(new OrderReferenceAdapter())).readAuthorizationAttributes("alice", stored));
        assertThrows(IllegalArgumentException.class, () -> this.codec.readAuthorizationAttributes("alice", stored));
        assertThrows(IllegalArgumentException.class, () -> new JdbcJsonCodec(List.of(adapter, adapter)));
        JdbcJsonValueAdapter<OrderReference> collidingClass = new OrderReferenceAdapter() {
            @Override
            public String typeId() {
                return "custom:another-order";
            }
        };
        assertThrows(IllegalArgumentException.class, () -> new JdbcJsonCodec(List.of(adapter, collidingClass)));
        JdbcJsonValueAdapter<OrderReference> reserved = new OrderReferenceAdapter() {
            @Override
            public String typeId() {
                return "identity";
            }
        };
        assertThrows(IllegalArgumentException.class, () -> new JdbcJsonCodec(List.of(reserved)));
    }

    @Test
    void adapterCannotAccidentallyEnableJacksonBeanSerialization() {
        JdbcJsonValueAdapter<OrderReference> adapter = new OrderReferenceAdapter() {
            @Override
            public JsonNode write(OrderReference value) {
                return new POJONode(value);
            }
        };
        JdbcJsonCodec custom = new JdbcJsonCodec(List.of(adapter));
        assertThrows(IllegalArgumentException.class, () -> custom.writeAuthorizationAttributes("alice",
                Map.of("order", new OrderReference("secret"))));
    }

    @Test
    void customAdapterJsonNumbersRetainDecimalPrecisionAndScale() {
        JdbcJsonValueAdapter<Amount> adapter = new JdbcJsonValueAdapter<>() {
            @Override
            public String typeId() {
                return "custom:amount";
            }

            @Override
            public Class<Amount> javaType() {
                return Amount.class;
            }

            @Override
            public JsonNode write(Amount value) {
                return DecimalNode.valueOf(value.value());
            }

            @Override
            public Amount read(JsonNode node) {
                return new Amount(node.decimalValue());
            }
        };
        JdbcJsonCodec custom = new JdbcJsonCodec(List.of(adapter));
        Map<String, Object> source = Map.of("amount",
                new Amount(new BigDecimal("12345678901234567890.1234567890123456789000")));
        assertEquals(source, custom.readAuthorizationAttributes("alice", custom.writeAuthorizationAttributes("alice", source)));
    }

    @ParameterizedTest
    @ValueSource(booleans = { false, true })
    void adapterNumbersMustRespectTheReadersLengthLimit(boolean negative) {
        JdbcJsonCodec custom = new JdbcJsonCodec(List.of(new JsonValueAdapter()));
        int limit = StreamReadConstraints.defaults().getMaxNumberLength();
        BigInteger boundary = BigInteger.TEN.pow(limit - 1);
        if (negative) {
            boundary = boundary.negate();
        }
        for (JsonNode number : List.of(BigIntegerNode.valueOf(boundary),
                DecimalNode.valueOf(new BigDecimal(boundary, 1)))) {
            Map<String, Object> source = Map.of("custom", new JsonValue(number));
            assertEquals(source,
                    custom.readAuthorizationAttributes("alice", custom.writeAuthorizationAttributes("alice", source)));
        }
        BigInteger oversized = boundary.multiply(BigInteger.TEN);
        for (JsonNode number : List.of(BigIntegerNode.valueOf(oversized),
                DecimalNode.valueOf(new BigDecimal(oversized, 1)))) {
            assertThrows(IllegalArgumentException.class,
                    () -> custom.writeAuthorizationAttributes("alice", Map.of("custom", new JsonValue(number))));
        }
    }

    @Test
    void fieldNamesMustRespectTheReadersLengthLimitInsideAndOutsideAdapters() {
        JdbcJsonCodec custom = new JdbcJsonCodec(List.of(new JsonValueAdapter()));
        String boundary = "x".repeat(StreamReadConstraints.defaults().getMaxNameLength());
        Map<String, Object> source = Map.of(boundary, "value");
        assertEquals(source,
                custom.readAuthorizationAttributes("alice", custom.writeAuthorizationAttributes("alice", source)));
        String oversized = boundary + "x";
        assertThrows(IllegalArgumentException.class,
                () -> custom.writeAuthorizationAttributes("alice", Map.of(oversized, "value")));
        JsonNode payload = this.json.createObjectNode().put(oversized, "value");
        assertThrows(IllegalArgumentException.class,
                () -> custom.writeAuthorizationAttributes("alice", Map.of("custom", new JsonValue(payload))));
    }

    @Test
    void builtInBigIntegersRemainTextEncodedAndKeepTheirPrecision() {
        BigInteger value = BigInteger.TEN.pow(StreamReadConstraints.defaults().getMaxNumberLength());
        Map<String, Object> source = Map.of("large-integer", value);
        assertEquals(source,
                this.codec.readAuthorizationAttributes("alice", this.codec.writeAuthorizationAttributes("alice", source)));
    }

    @Test
    void adapterCannotWriteATreeDeeperThanTheReaderAccepts() {
        JdbcJsonValueAdapter<OrderReference> adapter = new OrderReferenceAdapter() {
            @Override
            public JsonNode write(OrderReference value) {
                var root = json.createArrayNode();
                var current = root;
                for (int index = 0; index < 64; index++) {
                    current = current.addArray();
                }
                return root;
            }
        };
        JdbcJsonCodec custom = new JdbcJsonCodec(List.of(adapter));
        assertThrows(IllegalArgumentException.class, () -> custom.writeAuthorizationAttributes("alice",
                Map.of("order", new OrderReference("order-1"))));
    }

    @Test
    void applicationMapperConfigurationDoesNotChangeTheStorageContract() throws Exception {
        ObjectMapper applicationMapper = new ObjectMapper().setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        String before = this.codec.writeTokenSettings(TokenSettings.builder().build());
        applicationMapper.activateDefaultTyping(applicationMapper.getPolymorphicTypeValidator());
        assertEquals(before, new JdbcJsonCodec().writeTokenSettings(TokenSettings.builder().build()));
        assertEquals(this.json.readTree(JdbcJsonCodecTest.fixture("token-settings")), this.json.readTree(before));
        assertNull(this.json.getSerializationConfig().getDefaultTyper(null));
    }

    private static String fixture(String name) throws IOException {
        try (var input = JdbcJsonCodecTest.class.getResourceAsStream("/jdbc-json/" + name + ".json")) {
            assertNotNull(input, name);
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private record OrderReference(String id) {
    }

    private record Amount(BigDecimal value) {
    }

    private record JsonValue(JsonNode value) {
    }

    private static class JsonValueAdapter implements JdbcJsonValueAdapter<JsonValue> {
        @Override
        public String typeId() {
            return "custom:json-value";
        }

        @Override
        public Class<JsonValue> javaType() {
            return JsonValue.class;
        }

        @Override
        public JsonNode write(JsonValue value) {
            return value.value();
        }

        @Override
        public JsonValue read(JsonNode value) {
            return new JsonValue(value);
        }
    }

    private static class OrderReferenceAdapter implements JdbcJsonValueAdapter<OrderReference> {
        @Override
        public String typeId() {
            return "custom:order-reference";
        }

        @Override
        public Class<OrderReference> javaType() {
            return OrderReference.class;
        }

        @Override
        public JsonNode write(OrderReference value) {
            return TextNode.valueOf(value.id());
        }

        @Override
        public OrderReference read(JsonNode value) {
            if (!value.isTextual() || value.textValue().isBlank()) {
                throw new IllegalArgumentException("Expected order reference text");
            }
            return new OrderReference(value.textValue());
        }
    }
}
