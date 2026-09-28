package io.quarkiverse.authorization.server.deployment;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusDevModeTest;
import io.restassured.RestAssured;

class AuthorizationServerDevUITest {
    @RegisterExtension
    static final QuarkusDevModeTest app = new QuarkusDevModeTest()
            .withApplicationRoot(jar -> jar
                    .addClasses(LogoutTestApplication.class, LogoutTestApplication.PasswordProvider.class,
                            LogoutTestApplication.TrustedProvider.class)
                    .addAsResource("privateKey.pem").addAsResource("publicKey.pem")
                    .addAsResource(new StringAsset("""
                            quarkus:
                              http:
                                root-path: /api
                                auth:
                                  form:
                                    enabled: true
                                    login-page: custom/sign-in
                                    error-page: /custom/sign-in?error=true
                                    http-only-cookie: false
                              authorization-server:
                                default-login-page-enabled: true
                                token-endpoint: /custom/token
                                oidc:
                                  enabled: true
                                pushed-authorization-requests-enabled: true
                            """), "application.yml"));

    @Test
    void servesOverviewAndRefreshesBuildTimeDataAfterConfigurationChanges() throws Exception {
        String dataPath = "/api/q/dev-ui/quarkus-authorization-server-data.js";
        String data = RestAssured.given().basePath("").get(dataPath).then().statusCode(200).extract().asString();
        Assertions.assertTrue(data.contains("/api/custom/token"), data);
        Assertions.assertTrue(data.contains("/api/userinfo"), data);
        Assertions.assertTrue(data.contains("Other methods return 405"), data);
        String component = RestAssured.given().basePath("")
                .get("/api/q/dev-ui/quarkus-authorization-server/qwc-authorization-server-overview.js")
                .then().statusCode(200).extract().asString();
        Assertions.assertTrue(component.contains("class QwcAuthorizationServerOverview"), component);
        String extensions = RestAssured.given().basePath("").get("/api/q/dev-ui/devui-data.js").then().statusCode(200).extract()
                .asString();
        Assertions.assertTrue(extensions.contains("qwc-authorization-server-overview.js"), extensions);

        String rpcPath = "/api/q/dev-ui/json-rpc-ws";
        var missingIssuer = DevUIJsonRpcClient.overview(rpcPath, null);
        Assertions.assertEquals("ISSUER_NOT_CONFIGURED", missingIssuer.path("result").path("object").path("status").asText(),
                missingIssuer.toString());
        Assertions.assertFalse(missingIssuer.path("result").path("object").hasNonNull("issuer"));
        var projection = missingIssuer.path("result").path("object");
        Assertions.assertTrue(projection.path("login").path("formEnabled").asBoolean());
        Assertions.assertEquals("/custom/sign-in", projection.path("login").path("loginPage").asText());
        Assertions.assertEquals("/custom/sign-in", projection.path("login").path("landingPage").asText());
        Assertions.assertFalse(projection.path("login").path("httpOnlyCookie").asBoolean(),
                "Application override must take precedence over extension default");
        Assertions.assertEquals("LAX", projection.path("login").path("cookieSameSite").asText());
        var storage = projection.path("assembly").path("storage");
        Assertions.assertTrue(storage.get(0).path("defaultBean").asBoolean());
        Assertions.assertEquals("PRODUCER_METHOD", storage.get(0).path("kind").asText());
        var signing = projection.path("assembly").path("signing");
        Assertions.assertEquals("EPHEMERAL", signing.path("source").asText());
        Assertions.assertTrue(signing.path("initialized").asBoolean());
        Assertions.assertEquals(signing, DevUIJsonRpcClient.overview(rpcPath, null)
                .path("result").path("object").path("assembly").path("signing"), "Refresh must reuse the initialized keys");

        app.modifyResourceFile("application.yml", content -> content.replace("authorization-server:",
                "authorization-server:\n    issuer: https://public.example/gateway"));
        RestAssured.given().basePath("").get(dataPath).then().statusCode(200);
        var configured = DevUIJsonRpcClient.overview(rpcPath, null);
        Assertions.assertEquals("READY", configured.path("result").path("object").path("status").asText(),
                configured.toString());
        Assertions.assertEquals("https://public.example/gateway",
                configured.path("result").path("object").path("issuer").asText());
        app.modifyResourceFile("application.yml", content -> content.replace("custom/sign-in", "application/login"));
        RestAssured.given().basePath("").get(dataPath).then().statusCode(200);
        var updatedLogin = DevUIJsonRpcClient.overview(rpcPath, null).path("result").path("object").path("login");
        Assertions.assertEquals("/application/login", updatedLogin.path("loginPage").asText());
        Assertions.assertEquals("/application/login", updatedLogin.path("landingPage").asText());
        Assertions.assertEquals("UNKNOWN_TENANT",
                DevUIJsonRpcClient.overview(rpcPath, "missing").path("result").path("object").path("status").asText());
        Assertions.assertFalse(RestAssured.given().basePath("").get(dataPath).asString().contains("https://public.example"),
                "Runtime issuer must not be frozen in build-time data");

        app.modifyResourceFile("application.yml", content -> content.replace("/custom/token", "/changed/token"));
        String updated = RestAssured.given().basePath("").get(dataPath).then().statusCode(200).extract().asString();
        Assertions.assertTrue(updated.contains("/api/changed/token"), updated);
        Assertions.assertFalse(updated.contains("/api/custom/token"), updated);

        app.modifyResourceFile("application.yml", content -> content.replace("authorization-server:", """
                authorization-server:
                    signing:
                      key-id: configured-key
                      private-key-location: classpath:privateKey.pem
                      public-key-location: classpath:publicKey.pem"""));
        RestAssured.given().basePath("").get(dataPath).then().statusCode(200);
        var configuredSigning = DevUIJsonRpcClient.overview(rpcPath, null).path("result").path("object")
                .path("assembly").path("signing");
        Assertions.assertEquals("CONFIGURED_PEM", configuredSigning.path("source").asText());
        Assertions.assertEquals("configured-key", configuredSigning.path("activeKeyId").asText());
        Assertions.assertFalse(configuredSigning.toString().contains("privateKey.pem"));

        app.modifyResourceFile("application.yml",
                content -> content.replace("authorization-server:", "authorization-server:\n    enabled: false"));
        // Dev UI's SPA fallback can return HTML for an absent data module; the import map is authoritative.
        String index = RestAssured.given().basePath("").get("/api/q/dev-ui/").then().statusCode(200).extract().asString();
        Assertions.assertFalse(index.contains("quarkus-authorization-server-data.js"), index);
        String disabled = RestAssured.given().basePath("").get("/api/q/dev-ui/devui-data.js").then().statusCode(200).extract()
                .asString();
        Assertions.assertFalse(disabled.contains("qwc-authorization-server-overview.js"), disabled);
        Assertions.assertTrue(DevUIJsonRpcClient.overview(rpcPath, null).has("error"),
                "Disabled extension must not expose its JSON-RPC method");
    }
}
