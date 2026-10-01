package io.quarkiverse.authorization.server.jdbc;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.jose.jws.JwsAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.MacAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.identity.SecurityIdentity;

/** Logical value types only: no Java implementation names or polymorphic Jackson binding. */
final class JdbcJsonValues {

    static final int MAX_DEPTH = 64;
    private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

    private final Map<String, JdbcJsonValueAdapter<?>> adaptersById;
    private final Map<Class<?>, JdbcJsonValueAdapter<?>> adaptersByClass;

    JdbcJsonValues(List<JdbcJsonValueAdapter<?>> adapters) {
        Map<String, JdbcJsonValueAdapter<?>> ids = new HashMap<>();
        Map<Class<?>, JdbcJsonValueAdapter<?>> classes = new HashMap<>();
        for (JdbcJsonValueAdapter<?> adapter : List.copyOf(adapters)) {
            String id = Objects.requireNonNull(adapter.typeId(), "adapter typeId");
            Class<?> type = Objects.requireNonNull(adapter.javaType(), "adapter javaType");
            if (!id.matches("custom:[a-zA-Z0-9][a-zA-Z0-9._:-]*")
                    || type.isInterface() || type.isPrimitive() || type == Object.class
                    || JdbcJsonValues.isBuiltIn(type)) {
                throw new IllegalArgumentException("Invalid JDBC JSON adapter registration: " + id);
            }
            if (ids.putIfAbsent(id, adapter) != null || classes.putIfAbsent(type, adapter) != null) {
                throw new IllegalArgumentException("Duplicate JDBC JSON adapter registration: " + id);
            }
        }
        this.adaptersById = Map.copyOf(ids);
        this.adaptersByClass = Map.copyOf(classes);
    }

    JsonNode write(Object value, int depth) {
        JdbcJsonValues.checkDepth(depth);
        if (value == null) {
            return JSON.nullNode();
        }
        if (value instanceof String text) {
            return JSON.textNode(text);
        }
        if (value instanceof Boolean flag) {
            return JSON.booleanNode(flag);
        }
        String type = this.typeOf(value);
        ObjectNode node = JSON.objectNode().put("type", type);
        node.set("value", this.writeKnown(type, value, depth + 1));
        return node;
    }

    Object read(JsonNode node, int depth) {
        JdbcJsonValues.checkDepth(depth);
        if (node.isNull()) {
            return null;
        }
        if (node.isTextual()) {
            return node.textValue();
        }
        if (node.isBoolean()) {
            return node.booleanValue();
        }
        JdbcJsonValues.fields(node, Set.of("type", "value"), Set.of());
        return this.readKnown(JdbcJsonValues.text(node.get("type")), node.get("value"), depth + 1);
    }

    JsonNode writeKnown(String type, Object value, int depth) {
        JdbcJsonValues.checkDepth(depth);
        if (value == null || !(type.equals(this.typeOf(value))
                || type.equals("jws-algorithm") && value instanceof JwsAlgorithm)) {
            throw new IllegalArgumentException("Incorrect JDBC JSON value for " + type);
        }
        return switch (type) {
            case "text" -> JSON.textNode((String) value);
            case "boolean" -> JSON.booleanNode((Boolean) value);
            case "byte", "short", "integer", "long", "big-integer", "decimal", "instant", "duration" ->
                JSON.textNode(value.toString());
            case "float" -> JSON.textNode(JdbcJsonValues.finite((Float) value).toString());
            case "double" -> JSON.textNode(JdbcJsonValues.finite((Double) value).toString());
            case "map" -> this.writeMap((Map<?, ?>) value, depth + 1);
            case "list", "set" -> this.writeCollection((Iterable<?>) value, depth + 1);
            case "grant-type" -> JSON.textNode(((AuthorizationGrantType) value).getValue());
            case "client-authentication-method" -> JSON.textNode(((ClientAuthenticationMethod) value).getValue());
            case "signature-algorithm", "mac-algorithm", "jws-algorithm" -> JSON.textNode(((JwsAlgorithm) value).getName());
            case "token-format" -> JSON.textNode(((OAuth2TokenFormat) value).getValue());
            case "token-type" -> JSON.textNode(((OAuth2TokenType) value).getValue());
            case "identity" -> JdbcJsonDomainValues.writeIdentity((SecurityIdentity) value, this, depth + 1);
            case "authorization-request" -> JdbcJsonDomainValues.writeRequest((OAuth2AuthorizationRequest) value, this,
                    depth + 1);
            case "session" -> JdbcJsonDomainValues.writeSession((SessionInformation) value);
            default -> this.writeCustom(type, value);
        };
    }

    Object readKnown(String type, JsonNode node, int depth) {
        JdbcJsonValues.checkDepth(depth);
        return switch (type) {
            case "text" -> JdbcJsonValues.text(node);
            case "boolean" -> JdbcJsonValues.bool(node);
            case "byte" -> Byte.valueOf(JdbcJsonValues.text(node));
            case "short" -> Short.valueOf(JdbcJsonValues.text(node));
            case "integer" -> Integer.valueOf(JdbcJsonValues.text(node));
            case "long" -> Long.valueOf(JdbcJsonValues.text(node));
            case "big-integer" -> new BigInteger(JdbcJsonValues.text(node));
            case "decimal" -> new BigDecimal(JdbcJsonValues.text(node));
            case "float" -> JdbcJsonValues.finite(Float.valueOf(JdbcJsonValues.text(node)));
            case "double" -> JdbcJsonValues.finite(Double.valueOf(JdbcJsonValues.text(node)));
            case "instant" -> Instant.parse(JdbcJsonValues.text(node));
            case "duration" -> Duration.parse(JdbcJsonValues.text(node));
            case "map" -> this.readMap(node, depth + 1);
            case "list" -> this.readList(node, depth + 1);
            case "set" -> {
                List<Object> items = this.readList(node, depth + 1);
                Set<Object> set = new LinkedHashSet<>(items);
                if (set.size() != items.size()) {
                    throw new IllegalArgumentException("Duplicate JDBC JSON set element");
                }
                yield Collections.unmodifiableSet(set);
            }
            case "grant-type" -> new AuthorizationGrantType(JdbcJsonValues.text(node));
            case "client-authentication-method" -> new ClientAuthenticationMethod(JdbcJsonValues.text(node));
            case "signature-algorithm" -> JdbcJsonValues.knownAlgorithm(SignatureAlgorithm.from(JdbcJsonValues.text(node)));
            case "mac-algorithm" -> JdbcJsonValues.knownAlgorithm(MacAlgorithm.from(JdbcJsonValues.text(node)));
            case "jws-algorithm" -> JdbcJsonValues.algorithm(node);
            case "token-format" -> new OAuth2TokenFormat(JdbcJsonValues.text(node));
            case "token-type" -> new OAuth2TokenType(JdbcJsonValues.text(node));
            case "identity" -> JdbcJsonDomainValues.readIdentity(node, this, depth + 1);
            case "authorization-request" -> JdbcJsonDomainValues.readRequest(node, this, depth + 1);
            case "session" -> JdbcJsonDomainValues.readSession(node);
            default -> this.readCustom(type, node);
        };
    }

    ObjectNode writeMap(Map<?, ?> values, int depth) {
        JdbcJsonValues.checkDepth(depth);
        ObjectNode result = JSON.objectNode();
        values.forEach((key, value) -> {
            if (!(key instanceof String name)) {
                throw new IllegalArgumentException("JDBC JSON map keys must be strings");
            }
            try {
                result.set(name, this.write(value, depth + 1));
            } catch (IllegalArgumentException exception) {
                throw new IllegalArgumentException("Cannot encode JDBC JSON entry '" + name + "'", exception);
            }
        });
        return result;
    }

    Map<String, Object> readMap(JsonNode node, int depth) {
        JdbcJsonValues.checkDepth(depth);
        JdbcJsonValues.object(node);
        Map<String, Object> result = new LinkedHashMap<>();
        node.fields().forEachRemaining(entry -> {
            try {
                result.put(entry.getKey(), this.read(entry.getValue(), depth + 1));
            } catch (IllegalArgumentException exception) {
                throw new IllegalArgumentException("Cannot decode JDBC JSON entry '" + entry.getKey() + "'", exception);
            }
        });
        return Collections.unmodifiableMap(result);
    }

    private ArrayNode writeCollection(Iterable<?> values, int depth) {
        ArrayNode result = JSON.arrayNode();
        values.forEach(value -> result.add(this.write(value, depth + 1)));
        return result;
    }

    private List<Object> readList(JsonNode node, int depth) {
        if (!node.isArray()) {
            throw new IllegalArgumentException("Expected JDBC JSON array");
        }
        List<Object> result = new ArrayList<>();
        node.forEach(value -> result.add(this.read(value, depth + 1)));
        return Collections.unmodifiableList(result);
    }

    private String typeOf(Object value) {
        return switch (value) {
            case String ignored -> "text";
            case Boolean ignored -> "boolean";
            case Byte ignored -> "byte";
            case Short ignored -> "short";
            case Integer ignored -> "integer";
            case Long ignored -> "long";
            case BigInteger ignored -> "big-integer";
            case BigDecimal ignored -> "decimal";
            case Float ignored -> "float";
            case Double ignored -> "double";
            case Instant ignored -> "instant";
            case Duration ignored -> "duration";
            case Map<?, ?> ignored -> "map";
            case List<?> ignored -> "list";
            case Set<?> ignored -> "set";
            case AuthorizationGrantType ignored -> "grant-type";
            case ClientAuthenticationMethod ignored -> "client-authentication-method";
            case SignatureAlgorithm ignored -> "signature-algorithm";
            case MacAlgorithm ignored -> "mac-algorithm";
            case OAuth2TokenFormat ignored -> "token-format";
            case OAuth2TokenType ignored -> "token-type";
            case SecurityIdentity ignored -> "identity";
            case OAuth2AuthorizationRequest ignored -> "authorization-request";
            case SessionInformation ignored -> "session";
            default -> {
                JdbcJsonValueAdapter<?> adapter = this.adaptersByClass.get(value.getClass());
                if (adapter == null) {
                    throw new IllegalArgumentException("Unsupported JDBC JSON value type: " + value.getClass().getName());
                }
                yield adapter.typeId();
            }
        };
    }

    private <T> JsonNode writeCustom(String id, Object value) {
        @SuppressWarnings("unchecked")
        JdbcJsonValueAdapter<T> adapter = (JdbcJsonValueAdapter<T>) this.adaptersById.get(id);
        JsonNode result = adapter.write(adapter.javaType().cast(value));
        JdbcJsonValues.validateTree(result, 0);
        return result;
    }

    private Object readCustom(String id, JsonNode value) {
        JdbcJsonValueAdapter<?> adapter = this.adaptersById.get(id);
        if (adapter == null) {
            throw new IllegalArgumentException("Unknown JDBC JSON value type: " + id);
        }
        Object result = adapter.read(value);
        if (result == null || result.getClass() != adapter.javaType()) {
            throw new IllegalArgumentException("JDBC JSON adapter returned an incorrect value type");
        }
        return result;
    }

    private static boolean isBuiltIn(Class<?> type) {
        return List.of(String.class, Boolean.class, Byte.class, Short.class, Integer.class, Long.class,
                BigInteger.class, BigDecimal.class, Float.class, Double.class, Instant.class, Duration.class,
                Map.class, List.class, Set.class, AuthorizationGrantType.class, ClientAuthenticationMethod.class,
                JwsAlgorithm.class, OAuth2TokenFormat.class, OAuth2TokenType.class, SecurityIdentity.class,
                OAuth2AuthorizationRequest.class, SessionInformation.class).stream()
                .anyMatch(base -> base.isAssignableFrom(type));
    }

    static ObjectNode object(JsonNode node) {
        if (!(node instanceof ObjectNode object)) {
            throw new IllegalArgumentException("Expected JDBC JSON object");
        }
        return object;
    }

    static void fields(JsonNode node, Set<String> required, Set<String> optional) {
        ObjectNode object = JdbcJsonValues.object(node);
        for (String field : required) {
            if (!object.has(field)) {
                throw new IllegalArgumentException("Missing JDBC JSON field: " + field);
            }
        }
        object.fieldNames().forEachRemaining(field -> {
            if (!required.contains(field) && !optional.contains(field)) {
                throw new IllegalArgumentException("Unknown JDBC JSON field: " + field);
            }
        });
    }

    static String text(JsonNode node) {
        if (node == null || !node.isTextual()) {
            throw new IllegalArgumentException("Expected JDBC JSON string");
        }
        return node.textValue();
    }

    static boolean bool(JsonNode node) {
        if (node == null || !node.isBoolean()) {
            throw new IllegalArgumentException("Expected JDBC JSON boolean");
        }
        return node.booleanValue();
    }

    static Set<String> strings(JsonNode node) {
        if (node == null || !node.isArray()) {
            throw new IllegalArgumentException("Expected JDBC JSON string array");
        }
        Set<String> result = new LinkedHashSet<>();
        node.forEach(value -> {
            if (!result.add(JdbcJsonValues.text(value))) {
                throw new IllegalArgumentException("Duplicate JDBC JSON string array element");
            }
        });
        return Collections.unmodifiableSet(result);
    }

    private static JwsAlgorithm algorithm(JsonNode node) {
        String name = JdbcJsonValues.text(node);
        SignatureAlgorithm signature = SignatureAlgorithm.from(name);
        return signature != null ? signature : JdbcJsonValues.knownAlgorithm(MacAlgorithm.from(name));
    }

    private static JwsAlgorithm knownAlgorithm(JwsAlgorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Unknown JDBC JSON signing algorithm");
        }
        return algorithm;
    }

    static void validateTree(JsonNode node, int depth) {
        JdbcJsonValues.checkDepth(depth + 1);
        if (node == null || node.isPojo() || node.isMissingNode() || node.isBinary()) {
            throw new IllegalArgumentException("JDBC JSON adapter must return an ordinary JSON tree");
        }
        if (node.isFloatingPointNumber() && (node.isDouble() || node.isFloat()) && !Double.isFinite(node.doubleValue())) {
            throw new IllegalArgumentException("Non-finite JDBC JSON number");
        }
        node.forEach(child -> JdbcJsonValues.validateTree(child, depth + 1));
    }

    private static Float finite(Float number) {
        if (!Float.isFinite(number)) {
            throw new IllegalArgumentException("Non-finite JDBC JSON number");
        }
        return number;
    }

    private static Double finite(Double number) {
        if (!Double.isFinite(number)) {
            throw new IllegalArgumentException("Non-finite JDBC JSON number");
        }
        return number;
    }

    private static void checkDepth(int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("JDBC JSON values exceed the maximum nesting depth");
        }
    }
}
