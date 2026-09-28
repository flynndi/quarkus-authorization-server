package io.quarkiverse.authorization.server.runtime.jackson2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Permission;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.token.OAuth2TokenExchangeTokenCustomizers;
import io.quarkus.security.StringPermission;
import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

class QuarkusSecurityIdentityJacksonTest {

    private static final String IDENTITY = SecurityIdentity.class.getName();
    private static final String ACTORS = OAuth2TokenExchangeTokenCustomizers.ACTORS_ATTRIBUTE;
    private final ObjectMapper mapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .registerModule(new OAuth2AuthorizationServerJackson2Module());

    @Test
    void restoresQuarkusIdentityWithoutCredentialsRequestStateOrPermissionCheckers()
            throws Exception {
        Permission permission = new StringPermission("orders:write");
        SecurityIdentity original = QuarkusSecurityIdentity.builder()
                .setPrincipal(() -> "alice")
                .addRole("reader")
                .addCredential(new PasswordCredential("secret".toCharArray()))
                .addAttribute("request-only", new Object())
                .addPermissionChecker(ignored -> Uni.createFrom().item(true))
                .build();

        String json = write(original);
        SecurityIdentity restored = read(json);

        assertInstanceOf(QuarkusSecurityIdentity.class, restored);
        assertInstanceOf(QuarkusPrincipal.class, restored.getPrincipal());
        assertEquals("alice", restored.getPrincipal().getName());
        assertEquals(Set.of("reader"), restored.getRoles());
        assertFalse(restored.isAnonymous());
        assertTrue(restored.getCredentials().isEmpty());
        assertTrue(restored.getAttributes().isEmpty());
        assertFalse(restored.checkPermission(permission).await().indefinitely());
        assertFalse(json.contains("credentials"));
        assertFalse(json.contains("secret"));
        assertFalse(json.contains("request-only"));
        assertFalse(json.contains("permission"));
        assertNotNull(original.getCredential(PasswordCredential.class));
        assertTrue(original.checkPermission(permission).await().indefinitely());
    }

    @Test
    void preservesActorClaimsAndOrderWithoutFilteringNestedMaps() throws Exception {
        List<Map<String, Object>> actors = List.of(
                Map.of(
                        "sub",
                        "public-actor",
                        "iss",
                        "https://issuer.example",
                        "aud",
                        List.of("api"),
                        "may_act",
                        Map.of("sub", "next-actor")),
                Map.of("sub", "previous", "iss", "https://other.example"));
        SecurityIdentity original = QuarkusSecurityIdentity.builder(identity())
                .addAttribute(ACTORS, actors)
                .addAttribute("request-only", "omit")
                .build();

        SecurityIdentity restored = read(write(original));

        List<Map<String, Object>> restoredActors = restored.getAttribute(ACTORS);
        assertEquals(actors, restoredActors);
        assertEquals(Set.of(ACTORS), restored.getAttributes().keySet());
        assertThrows(UnsupportedOperationException.class, () -> restoredActors.add(Map.of()));
        assertThrows(
                UnsupportedOperationException.class,
                () -> restoredActors.getFirst().put("sub", "changed"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "missing-principal",
            "blank-principal",
            "null-principal",
            "number-principal",
            "principal-object",
            "number-role",
            "boolean-role",
            "null-role",
            "null-roles",
            "credentials",
            "permissions",
            "anonymous",
            "role",
            "permissionAsString",
            "null-actors",
            "nonlist-actors",
            "unknown-attribute",
            "missing-actor-sub",
            "blank-actor-sub",
            "invalid-actor-issuer"
    })
    void rejectsMalformedOrRuntimeOnlyIdentityProperties(String mutation) throws Exception {
        ObjectNode root = (ObjectNode) this.mapper.readTree(write(identity()));
        ObjectNode data = (ObjectNode) root.get(IDENTITY);
        switch (mutation) {
            case "missing-principal" -> data.remove("principal");
            case "blank-principal" -> data.put("principal", " ");
            case "null-principal" -> data.putNull("principal");
            case "number-principal" -> data.put("principal", 123);
            case "principal-object" ->
                data.putObject("principal").put("@class", "java.lang.Runtime");
            case "number-role" -> ((ArrayNode) data.get("roles").get(1)).removeAll().add(5);
            case "boolean-role" -> ((ArrayNode) data.get("roles").get(1)).removeAll().add(true);
            case "null-role" -> ((ArrayNode) data.get("roles").get(1)).removeAll().addNull();
            case "null-roles" -> data.putNull("roles");
            case "credentials" -> data.put("credentials", "secret");
            case "permissions" -> data.put("permissions", "admin");
            case "anonymous" -> data.put("anonymous", false);
            case "role", "permissionAsString" -> data.put(mutation, "admin");
            case "null-actors" -> ((ObjectNode) data.get("attributes")).putNull(ACTORS);
            case "nonlist-actors" -> ((ObjectNode) data.get("attributes")).put(ACTORS, "actor");
            case "unknown-attribute" ->
                ((ObjectNode) data.get("attributes")).put("request-only", "value");
            default -> {
                Map<String, Object> actor = switch (mutation) {
                    case "missing-actor-sub" -> Map.of("iss", "issuer");
                    case "blank-actor-sub" -> Map.of("sub", " ");
                    default -> Map.of("sub", "actor", "iss", 5);
                };
                data.set(
                        "attributes",
                        this.mapper.valueToTree(
                                new LinkedHashMap<>(Map.of(ACTORS, List.of(actor)))));
            }
        }
        assertThrows(JsonMappingException.class, () -> read(root.toString()));
    }

    @Test
    void onlyAllowsTheExactQuarkusIdentityType() throws Exception {
        ObjectNode root = (ObjectNode) this.mapper.readTree(write(identity()));
        ((ObjectNode) root.get(IDENTITY)).put("@class", UnapprovedIdentity.class.getName());
        assertThrows(InvalidTypeIdException.class, () -> read(root.toString()));
        ((ObjectNode) root.get(IDENTITY))
                .put("@class", SecurityIdentityJacksonBuilder.class.getName());
        assertThrows(InvalidTypeIdException.class, () -> read(root.toString()));
    }

    @Test
    void identityAnnotationsDoNotChangeAnUnconfiguredMapper() throws Exception {
        ObjectMapper applicationMapper = new ObjectMapper();
        assertNull(applicationMapper.findMixInClassFor(QuarkusSecurityIdentity.class));
        assertNull(applicationMapper.findMixInClassFor(QuarkusPrincipal.class));
        assertFalse(
                applicationMapper
                        .writeValueAsString(Map.of("ordinary", "value"))
                        .contains("@class"));
    }

    private String write(SecurityIdentity identity) throws Exception {
        return this.mapper.writeValueAsString(
                Collections.unmodifiableMap(new LinkedHashMap<>(Map.of(IDENTITY, identity))));
    }

    private SecurityIdentity read(String json) throws Exception {
        Map<String, Object> attributes = this.mapper.readValue(json, new TypeReference<>() {
        });
        return (SecurityIdentity) attributes.get(IDENTITY);
    }

    private static SecurityIdentity identity() {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("alice"))
                .addRole("reader")
                .build();
    }

    // Loadable, but excluded by the exact identity type allow-list.
    private abstract static class UnapprovedIdentity implements SecurityIdentity {
    }
}
