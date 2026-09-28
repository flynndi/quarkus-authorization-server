package io.quarkiverse.authorization.server.deployment;

import java.util.HashSet;
import java.util.Set;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.fasterxml.jackson.databind.JsonNode;

import io.quarkus.test.QuarkusDevModeTest;
import io.restassured.RestAssured;

class AuthorizationServerDevUICustomAssemblyTest {
    @RegisterExtension
    static final QuarkusDevModeTest app = new QuarkusDevModeTest().withApplicationRoot(jar -> jar
            .addClasses(DevUIAssemblyTestSupport.class, DevUICustomAssemblyTestApplication.class,
                    DevUIAssemblyTestSupport.OnceKeySource.class, DevUIAssemblyTestSupport.UnqueriedClients.class)
            .addAsResource(new StringAsset("""
                    quarkus:
                      authorization-server:
                        issuer: https://server.example
                        clients:
                          config-only-client:
                            client-secret: sensitive-client-secret
                            authorization-grant-types: client_credentials
                        signing:
                          private-key-location: sensitive-unused-location
                    """), "application.yml"));

    @Test
    void inspectsSelectedBeanDefinitionsAndExistingKeysWithoutReadingApplicationData() throws Exception {
        var result = DevUIJsonRpcClient.overview("/q/dev-ui/json-rpc-ws", null).path("result").path("object");
        Assertions.assertFalse(result.path("login").path("formEnabled").asBoolean());
        var storage = result.path("assembly").path("storage");
        Assertions.assertEquals(DevUICustomAssemblyTestApplication.class.getName(), storage.get(0).path("className").asText());
        Assertions.assertEquals("PRODUCER_METHOD", storage.get(0).path("kind").asText());
        Assertions.assertFalse(storage.get(0).path("defaultBean").asBoolean());
        var signing = result.path("assembly").path("signing");
        Assertions.assertTrue(signing.path("initialized").asBoolean(), result.toString());
        Assertions.assertEquals("APPLICATION_SOURCE", signing.path("source").asText());
        Assertions.assertEquals("application-key", signing.path("activeKeyId").asText());
        Assertions.assertEquals("RS256", signing.path("keys").get(0).path("algorithm").asText());
        Assertions.assertEquals(signing, DevUIJsonRpcClient.overview("/q/dev-ui/json-rpc-ws", null)
                .path("result").path("object").path("assembly").path("signing"));
        AuthorizationServerDevUICustomAssemblyTest.fields(result,
                "multipleIssuers", "tenantIds", "issuer", "status", "login", "assembly");
        AuthorizationServerDevUICustomAssemblyTest.fields(result.path("assembly"), "storage", "signing");
        AuthorizationServerDevUICustomAssemblyTest.fields(signing, "source", "provider", "activeKeyId", "keys", "initialized");
        AuthorizationServerDevUICustomAssemblyTest.fields(signing.path("keys").get(0), "keyId", "algorithm");
        for (var component : storage) {
            AuthorizationServerDevUICustomAssemblyTest.fields(component, "role", "className", "kind", "scope", "defaultBean");
        }
        Assertions.assertFalse(result.toString().contains("sensitive-"));
        Assertions.assertFalse(result.toString().contains("config-only-client"));

        // An application can replace the manager itself with a dependent producer. Inspect its metadata only.
        app.modifySourceFile(DevUICustomAssemblyTestApplication.class, content -> content
                .replace("@Singleton\n    AuthorizationServerKeySource source()", "@jakarta.enterprise.context.Dependent\n    "
                        + "io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager source()")
                .replace("return new DevUIAssemblyTestSupport.OnceKeySource(\"application-key\");",
                        "return new io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager("
                                + "new DevUIAssemblyTestSupport.OnceKeySource(\"application-key\"));"));
        RestAssured.get("/q/dev-ui/").then().statusCode(200);
        var applicationManager = DevUIJsonRpcClient.overview("/q/dev-ui/json-rpc-ws", null)
                .path("result").path("object").path("assembly").path("signing");
        Assertions.assertEquals("APPLICATION_MANAGER", applicationManager.path("source").asText(),
                applicationManager.toString());
        Assertions.assertEquals("Dependent", applicationManager.path("provider").path("scope").asText());
        Assertions.assertFalse(applicationManager.path("initialized").asBoolean());
        Assertions.assertTrue(applicationManager.path("keys").isEmpty());
    }

    private static void fields(JsonNode value, String... expected) {
        Set<String> fields = new HashSet<>();
        value.fieldNames().forEachRemaining(fields::add);
        Assertions.assertEquals(Set.of(expected), fields);
    }
}
