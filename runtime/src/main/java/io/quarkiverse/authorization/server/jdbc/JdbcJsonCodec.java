package io.quarkiverse.authorization.server.jdbc;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.cfg.JsonNodeFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTokenBinding;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.settings.ConfigurationSettingNames;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * Explicit JSON contract for JDBC columns. Uses its own immutable mapper configuration and
 * explicit tree binding; application Jackson configuration and Java class names are not storage metadata.
 * This codec is usable without CDI. Application value adapters must be thread-safe.
 */
public final class JdbcJsonCodec {

    private static final List<Field> AUTHORIZATION_FIELDS = List.of(
            new Field(SecurityIdentity.class.getName(), "identity", "identity"),
            new Field(OAuth2AuthorizationRequest.class.getName(), "authorizationRequest", "authorization-request"),
            new Field(SessionInformation.class.getName(), "session", "session"),
            new Field(OAuth2AuthorizationRequest.PUSHED_REQUEST_EXPIRES_AT_ATTRIBUTE_NAME, "pushedRequestExpiresAt",
                    "instant"));
    private static final List<Field> METADATA_FIELDS = List.of(
            new Field(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, "invalidated", "boolean"),
            new Field(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, "claims", "map"),
            new Field(OAuth2TokenFormat.class.getName(), "tokenFormat", "text"),
            new Field(DPoPTokenBinding.REFRESH_JKT_METADATA, "dpopRefreshJkt", "text"));
    private static final List<Field> CLIENT_FIELDS = List.of(
            new Field(ConfigurationSettingNames.Client.REQUIRE_PROOF_KEY, "requireProofKey", "boolean"),
            new Field(ConfigurationSettingNames.Client.REQUIRE_AUTHORIZATION_CONSENT, "requireAuthorizationConsent", "boolean"),
            new Field(ConfigurationSettingNames.Client.JWK_SET_URL, "jwkSetUrl", "text"),
            new Field(ConfigurationSettingNames.Client.TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM,
                    "tokenEndpointAuthenticationSigningAlgorithm", "jws-algorithm"),
            new Field(ConfigurationSettingNames.Client.X509_CERTIFICATE_SUBJECT_DN, "x509CertificateSubjectDn", "text"));
    private static final List<Field> TOKEN_FIELDS = List.of(
            new Field(ConfigurationSettingNames.Token.AUTHORIZATION_CODE_TIME_TO_LIVE, "authorizationCodeTimeToLive",
                    "duration"),
            new Field(ConfigurationSettingNames.Token.ACCESS_TOKEN_TIME_TO_LIVE, "accessTokenTimeToLive", "duration"),
            new Field(ConfigurationSettingNames.Token.ACCESS_TOKEN_FORMAT, "accessTokenFormat", "token-format"),
            new Field(ConfigurationSettingNames.Token.DEVICE_CODE_TIME_TO_LIVE, "deviceCodeTimeToLive", "duration"),
            new Field(ConfigurationSettingNames.Token.REUSE_REFRESH_TOKENS, "reuseRefreshTokens", "boolean"),
            new Field(ConfigurationSettingNames.Token.REFRESH_TOKEN_TIME_TO_LIVE, "refreshTokenTimeToLive", "duration"),
            new Field(ConfigurationSettingNames.Token.ID_TOKEN_SIGNATURE_ALGORITHM, "idTokenSignatureAlgorithm",
                    "signature-algorithm"));

    private final ObjectMapper mapper;
    private final JdbcJsonValues values;

    public JdbcJsonCodec() {
        this(List.of());
    }

    public JdbcJsonCodec(List<JdbcJsonValueAdapter<?>> adapters) {
        this.mapper = JsonMapper.builder(JsonFactory.builder()
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(JdbcJsonValues.MAX_DEPTH).build())
                .build())
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
                .disable(JsonNodeFeature.STRIP_TRAILING_BIGDECIMAL_ZEROES)
                .build();
        this.values = new JdbcJsonValues(adapters);
    }

    public String writeAuthorizationAttributes(String principalName, Map<String, Object> attributes) {
        JdbcJsonCodec.validateSubject(principalName, attributes);
        return this.writeDocument("authorization-attributes", attributes, AUTHORIZATION_FIELDS);
    }

    public Map<String, Object> readAuthorizationAttributes(String principalName, String json) {
        Map<String, Object> attributes = this.readDocument("authorization-attributes", json, AUTHORIZATION_FIELDS);
        JdbcJsonCodec.validateSubject(principalName, attributes);
        return attributes;
    }

    public String writeTokenMetadata(Map<String, Object> metadata) {
        JdbcJsonCodec.validateClaims(metadata);
        return this.writeDocument("token-metadata", metadata, METADATA_FIELDS);
    }

    public Map<String, Object> readTokenMetadata(String json) {
        Map<String, Object> metadata = this.readDocument("token-metadata", json, METADATA_FIELDS);
        JdbcJsonCodec.validateClaims(metadata);
        return metadata;
    }

    public String writeClientSettings(ClientSettings settings) {
        return this.writeDocument("client-settings", settings.getSettings(), CLIENT_FIELDS);
    }

    public ClientSettings readClientSettings(String json) {
        return ClientSettings.builder().settings(settings -> settings.putAll(
                this.readDocument("client-settings", json, CLIENT_FIELDS))).build();
    }

    public String writeTokenSettings(TokenSettings settings) {
        return this.writeDocument("token-settings", settings.getSettings(), TOKEN_FIELDS);
    }

    public TokenSettings readTokenSettings(String json) {
        return TokenSettings.builder().settings(settings -> settings.putAll(
                this.readDocument("token-settings", json, TOKEN_FIELDS))).build();
    }

    private String writeDocument(String kind, Map<String, Object> source, List<Field> fields) {
        Objects.requireNonNull(source, "JDBC JSON values");
        ObjectNode root = this.mapper.createObjectNode().put("kind", kind);
        ObjectNode data = root.putObject("data");
        Map<String, Object> extensions = new LinkedHashMap<>(source);
        for (Field field : fields) {
            if (extensions.containsKey(field.key())) {
                data.set(field.name(), this.values.writeKnown(field.type(), extensions.remove(field.key()), 0));
            }
        }
        data.set("extensions", this.values.writeMap(extensions, 0));
        // Reject unsupported node types and cycles before serialization.
        JdbcJsonValues.validateTree(root, 0);
        try {
            String json = this.mapper.writeValueAsString(root);
            // Tree serialization does not enforce StreamReadConstraints. Use the actual reader
            // before JDBC can persist the document; this binds no domain objects or application adapters.
            this.mapper.readTree(json);
            return json;
        } catch (JsonProcessingException exception) {
            throw new IllegalArgumentException("Unable to encode JDBC JSON " + kind, exception);
        }
    }

    private Map<String, Object> readDocument(String kind, String json, List<Field> fields) {
        Arguments.requireNonBlank(json, "JDBC JSON document");
        try {
            ObjectNode root = JdbcJsonValues.object(this.mapper.readTree(json));
            JdbcJsonValues.fields(root, Set.of("kind", "data"), Set.of());
            if (!kind.equals(JdbcJsonValues.text(root.get("kind")))) {
                throw new IllegalArgumentException("Unexpected JDBC JSON document kind");
            }
            ObjectNode data = JdbcJsonValues.object(root.get("data"));
            JdbcJsonValues.fields(data, Set.of("extensions"), fields.stream().map(Field::name).collect(Collectors.toSet()));
            Map<String, Object> result = new LinkedHashMap<>(this.values.readMap(data.get("extensions"), 0));
            for (Field field : fields) {
                if (result.containsKey(field.key())) {
                    throw new IllegalArgumentException("Reserved JDBC JSON key in extensions: " + field.name());
                }
                if (data.has(field.name())) {
                    result.put(field.key(), this.values.readKnown(field.type(), data.get(field.name()), 0));
                }
            }
            return Collections.unmodifiableMap(result);
        } catch (JsonProcessingException | RuntimeException exception) {
            throw new IllegalArgumentException("Unable to decode JDBC JSON " + kind, exception);
        }
    }

    private static void validateSubject(String principalName, Map<String, Object> attributes) {
        Arguments.requireNonBlank(principalName, "authorization principalName");
        if (attributes.containsKey(SecurityIdentity.class.getName())) {
            Object value = attributes.get(SecurityIdentity.class.getName());
            if (!(value instanceof SecurityIdentity identity) || identity.isAnonymous() || identity.getPrincipal() == null
                    || !principalName.equals(identity.getPrincipal().getName())) {
                throw new IllegalArgumentException("Authorization identity must match principalName and be authenticated");
            }
        }
        if (attributes.containsKey(SessionInformation.class.getName())) {
            Object value = attributes.get(SessionInformation.class.getName());
            if (!(value instanceof SessionInformation session) || !principalName.equals(session.principalName())) {
                throw new IllegalArgumentException("Authorization session must match principalName");
            }
        }
    }

    private static void validateClaims(Map<String, Object> metadata) {
        Object claims = metadata.get(OAuth2Authorization.Token.CLAIMS_METADATA_NAME);
        if (claims instanceof Map<?, ?> values && values.containsKey("nbf") && !(values.get("nbf") instanceof Instant)) {
            throw new IllegalArgumentException("Persisted nbf claim must be an Instant");
        }
    }

    private record Field(String key, String name, String type) {
    }
}
