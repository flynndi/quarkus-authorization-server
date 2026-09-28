# Tokens and resource servers

The authorization server issues tokens. A resource server validates access tokens and applies its own access rules. The examples put both roles in one application for convenience; the same token boundary applies when they run in separate processes.

## Choose a token representation

| Representation | Client setting | Resource-server validation |
| --- | --- | --- |
| Signed JWT | `access-token-format=self-contained` (default) | Verify the signature using the issuer's JWKS, then validate claims |
| Opaque reference token | `access-token-format=reference` | Authenticate to the issuer's introspection endpoint and check the result |

An ID Token describes an OIDC authentication result for the client. Send the **access token**, not the ID Token, to the resource API. JWT decoding alone does not verify a signature or establish that a token is valid.

## Configure a JWT resource server

Add `io.quarkus:quarkus-oidc` to the resource application. This configuration matches the Client Credentials example's issuer and client ID:

```properties
quarkus.oidc.application-type=service
quarkus.oidc.auth-server-url=http://localhost:8080
quarkus.oidc.discovery-enabled=true
quarkus.oidc.token.audience=machine-client
quarkus.oidc.token.allow-jwt-introspection=false
quarkus.oidc.token.allow-opaque-token-introspection=false
```

The authorization server must expose OIDC discovery for this setup (`quarkus.authorization-server.oidc.enabled=true`). In a deployed application, use its public HTTPS issuer. The resource API can then require a scope:

```java
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import io.quarkus.security.PermissionsAllowed;

@Path("/api/messages")
public class MessageResource {
    @GET
    @PermissionsAllowed("message.read")
    public String messages() {
        return "Hello from the protected API";
    }
}
```

This resource example uses Quarkus REST in addition to `quarkus-oidc`; it does not define authorization-server routes. When Form and Bearer authentication coexist, select Bearer for `/api/*` as shown in the [Code guide](./authorization-code#keep-browser-login-and-api-authentication-separate).

The default JWT audience is the registered client ID. Use the correct client ID in the resource configuration, or deliberately customize the access-token audience and update resource validation to match. Never disable audience checking just to accommodate a mismatch.

Sources: [`application.yml`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/client-credentials/src/main/resources/application.yml), [`MessageResource`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/client-credentials/src/main/java/io/quarkiverse/authorization/server/example/clientcredentials/MessageResource.java), [`JwtGenerator`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/token/JwtGenerator.java).

## Add application claims

Provide a CDI `OAuth2TokenCustomizer<JwtEncodingContext>` to add claims without replacing signing or token generation. For example, expose the principal's roles on user access tokens:

```java
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;

@Singleton
public class TokenClaims {
    @Produces
    @Singleton
    OAuth2TokenCustomizer<JwtEncodingContext> userAccessTokenClaims() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                    && !AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                context.getClaims().claim("groups", context.getPrincipal().getRoles());
            }
        };
    }
}
```

The token-type check matters: the JWT customizer also participates in ID Token generation. `quarkus-oidc` can read `groups` as roles, which can then be checked with `@RolesAllowed`. This sample copies all principal roles; narrow that set for your API's needs. The principal can be a historical authorization snapshot, especially during refresh; see [identity and access](./identity-and-access#identity-changes-after-authorization).

For reference access tokens use `OAuth2TokenCustomizer<OAuth2TokenClaimsContext>`. Several default-qualified customizers compose; higher `@Priority` values run first, and equal priorities have no promised order. Replacing the whole `OAuth2TokenGenerator` makes the application responsible for the entire generation chain.

## Expiration, revocation and DPoP

Revocation updates authorization-server state. A resource server validating JWTs locally does not consult that state on every request; a valid signature alone cannot tell it that the server has revoked a token. Decide whether short lifetimes, introspection or an application policy meets your needs. The JWT-only configuration above intentionally rejects opaque tokens.

DPoP is optional for clients in supported flows. A DPoP-bound access token also needs resource-side proof validation; it cannot be sent as an ordinary Bearer token. Existing resource interoperability tests cover `quarkus-oidc` and additional proof/replay checks. See the [integration-test sources](https://github.com/flynndi/quarkus-authorization-server/tree/main/integration-tests) for that advanced setup; the basic configuration above does not enable it.
