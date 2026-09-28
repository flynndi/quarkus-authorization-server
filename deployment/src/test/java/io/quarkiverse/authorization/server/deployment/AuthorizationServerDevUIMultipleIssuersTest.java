package io.quarkiverse.authorization.server.deployment;

import java.util.HashSet;
import java.util.Set;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusDevModeTest;
import io.restassured.RestAssured;

class AuthorizationServerDevUIMultipleIssuersTest {
    @RegisterExtension
    static final QuarkusDevModeTest app = new QuarkusDevModeTest().withApplicationRoot(jar -> jar
            .addClasses(DevUIAssemblyTestSupport.class, DevUITenantTestApplication.class,
                    DevUIAssemblyTestSupport.OnceKeySource.class, DevUIAssemblyTestSupport.UnqueriedClients.class)
            .addAsResource(new StringAsset("""
                    quarkus:
                      http:
                        root-path: /server
                      authorization-server:
                        multiple-issuers-allowed: true
                        issuers:
                          beta: https://public.example/server/beta
                          alpha: https://public.example/server/alpha
                        oidc:
                          enabled: true
                    """), "application.yml"));

    @Test
    void resolvesOnlyAnExplicitTenantAndRefreshesItsRuntimeIssuer() throws Exception {
        String rpcPath = "/server/q/dev-ui/json-rpc-ws";
        var initial = DevUIJsonRpcClient.overview(rpcPath, null);
        Assertions.assertEquals("SELECT_TENANT", initial.path("result").path("object").path("status").asText(),
                initial.toString());
        Assertions.assertEquals("[\"alpha\",\"beta\"]", initial.path("result").path("object").path("tenantIds").toString());
        Assertions.assertFalse(initial.path("result").path("object").hasNonNull("issuer"));
        Assertions.assertFalse(initial.path("result").path("object").hasNonNull("assembly"));

        for (String id : Set.of("alpha", "beta")) {
            var result = DevUIJsonRpcClient.overview(rpcPath, id).path("result").path("object");
            Assertions.assertEquals("READY", result.path("status").asText(), result.toString());
            Assertions.assertEquals(id, result.path("tenantId").asText());
            Assertions.assertEquals("https://public.example/server/" + id, result.path("issuer").asText());
            Set<String> fields = new HashSet<>();
            result.fieldNames().forEachRemaining(fields::add);
            Assertions.assertEquals(Set.of("multipleIssuers", "tenantIds", "tenantId", "issuer", "status", "login", "assembly"),
                    fields);
            var signing = result.path("assembly").path("signing");
            Assertions.assertTrue(signing.path("initialized").asBoolean(), result.toString());
            Assertions.assertEquals(id, signing.path("activeKeyId").asText());
            Assertions.assertEquals("TENANT_SOURCE", signing.path("source").asText());
            Assertions.assertEquals("TENANT_COMPONENT", result.path("assembly").path("storage").get(0).path("kind").asText());
            Assertions.assertEquals(signing, DevUIJsonRpcClient.overview(rpcPath, id)
                    .path("result").path("object").path("assembly").path("signing"));
        }
        var unknown = DevUIJsonRpcClient.overview(rpcPath, "unknown").path("result").path("object");
        Assertions.assertEquals("UNKNOWN_TENANT", unknown.path("status").asText());
        Assertions.assertFalse(unknown.hasNonNull("issuer"));
        Assertions.assertFalse(unknown.hasNonNull("assembly"));

        app.modifyResourceFile("application.yml",
                content -> content.replace("https://public.example", "https://proxy.example"));
        RestAssured.given().basePath("").get("/server/q/dev-ui/").then().statusCode(200);
        Assertions.assertEquals("https://proxy.example/server/beta",
                DevUIJsonRpcClient.overview(rpcPath, "beta").path("result").path("object").path("issuer").asText());
    }
}
