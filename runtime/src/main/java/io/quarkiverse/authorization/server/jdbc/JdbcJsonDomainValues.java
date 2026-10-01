package io.quarkiverse.authorization.server.jdbc;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.token.OAuth2TokenExchangeTokenCustomizers;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

/** Explicit protocol snapshots, independent of Jackson's view of the runtime implementation. */
final class JdbcJsonDomainValues {

    private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

    private JdbcJsonDomainValues() {
    }

    static ObjectNode writeIdentity(SecurityIdentity identity, JdbcJsonValues values, int depth) {
        if (identity.isAnonymous() || identity.getPrincipal() == null) {
            throw new IllegalArgumentException("Persisted identity must be authenticated");
        }
        String name = Arguments.requireNonBlank(identity.getPrincipal().getName(), "identity principalName");
        ObjectNode node = JSON.objectNode().put("principalName", name);
        node.set("roles", JdbcJsonDomainValues.writeStrings(identity.getRoles()));
        ArrayNode actors = node.putArray("actors");
        for (Map<String, Object> actor : OAuth2TokenExchangeTokenCustomizers.getActors(identity)) {
            actors.add(values.writeMap(actor, depth));
        }
        return node;
    }

    static SecurityIdentity readIdentity(JsonNode node, JdbcJsonValues values, int depth) {
        JdbcJsonValues.fields(node, Set.of("principalName", "roles", "actors"), Set.of());
        String name = Arguments.requireNonBlank(JdbcJsonValues.text(node.get("principalName")), "identity principalName");
        JsonNode actors = node.get("actors");
        if (!actors.isArray()) {
            throw new IllegalArgumentException("Persisted identity actors must be an array");
        }
        List<Map<String, Object>> actorMaps = new ArrayList<>();
        actors.forEach(actor -> actorMaps.add(values.readMap(actor, depth)));
        List<Map<String, Object>> validatedActors = OAuth2TokenExchangeTokenCustomizers.getActors(
                Map.of(OAuth2TokenExchangeTokenCustomizers.ACTORS_ATTRIBUTE, actorMaps));
        var builder = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(name))
                .addRoles(JdbcJsonValues.strings(node.get("roles")));
        if (!validatedActors.isEmpty()) {
            builder.addAttribute(OAuth2TokenExchangeTokenCustomizers.ACTORS_ATTRIBUTE, validatedActors);
        }
        return builder.build();
    }

    static ObjectNode writeSession(SessionInformation session) {
        return JSON.objectNode()
                .put("principalName", session.principalName())
                .put("sessionId", session.sessionId())
                .put("authenticationTime", session.authenticationTime().toString());
    }

    static SessionInformation readSession(JsonNode node) {
        JdbcJsonValues.fields(node, Set.of("principalName", "sessionId", "authenticationTime"), Set.of());
        return new SessionInformation(JdbcJsonValues.text(node.get("principalName")),
                JdbcJsonValues.text(node.get("sessionId")),
                Instant.parse(JdbcJsonValues.text(node.get("authenticationTime"))));
    }

    static ObjectNode writeRequest(OAuth2AuthorizationRequest request, JdbcJsonValues values, int depth) {
        ObjectNode node = JSON.objectNode()
                .put("authorizationUri", request.getAuthorizationUri())
                .put("grantType", request.getGrantType().getValue())
                .put("responseType", request.getResponseType().getValue())
                .put("clientId", request.getClientId())
                .put("redirectUri", request.getRedirectUri())
                .put("state", request.getState())
                .put("authorizationRequestUri", request.getAuthorizationRequestUri());
        node.set("scopes", JdbcJsonDomainValues.writeStrings(request.getScopes()));
        node.set("additionalParameters", values.writeMap(request.getAdditionalParameters(), depth));
        node.set("attributes", values.writeMap(request.getAttributes(), depth));
        return node;
    }

    static OAuth2AuthorizationRequest readRequest(JsonNode node, JdbcJsonValues values, int depth) {
        JdbcJsonValues.fields(node, Set.of("authorizationUri", "grantType", "responseType", "clientId", "redirectUri",
                "state", "authorizationRequestUri", "scopes", "additionalParameters", "attributes"), Set.of());
        if (!"authorization_code".equals(JdbcJsonValues.text(node.get("grantType")))
                || !"code".equals(JdbcJsonValues.text(node.get("responseType")))) {
            throw new IllegalArgumentException("Unsupported persisted authorization request type");
        }
        String requestUri = Arguments.requireNonBlank(JdbcJsonValues.text(node.get("authorizationRequestUri")),
                "authorizationRequestUri");
        return OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(JdbcJsonValues.text(node.get("authorizationUri")))
                .clientId(JdbcJsonValues.text(node.get("clientId")))
                .redirectUri(JdbcJsonDomainValues.nullableText(node.get("redirectUri")))
                .state(JdbcJsonDomainValues.nullableText(node.get("state")))
                .authorizationRequestUri(requestUri)
                .scopes(JdbcJsonValues.strings(node.get("scopes")))
                .additionalParameters(values.readMap(node.get("additionalParameters"), depth))
                .attributes(values.readMap(node.get("attributes"), depth))
                .build();
    }

    private static String nullableText(JsonNode node) {
        return node.isNull() ? null : JdbcJsonValues.text(node);
    }

    private static ArrayNode writeStrings(Set<String> values) {
        ArrayNode node = JSON.arrayNode();
        // Check runtime elements too: callers may supply a raw collection through an identity implementation.
        for (Object value : values) {
            if (!(value instanceof String text)) {
                throw new IllegalArgumentException("Persisted roles and scopes must be strings");
            }
            node.add(text);
        }
        return node;
    }
}
