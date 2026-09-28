# Getting Started

Add Quarkus Authorization Server to your own application, sign in through its default pages, obtain an access token with **Authorization Code**, and call an API protected by **`quarkus-oidc`**.

This guide uses one Quarkus application for both the authorization server and resource server. A browser and a few terminal commands act as the OAuth client. You do not need this repository's source, a frontend build, or a database.

You need **JDK 21**, **Maven 3.9+**, **curl 7.76+**, **Python 3**, and a browser. Keep port `8080` free and use `localhost` consistently, including the callback URL.

## 1. Add the dependencies

Create a Quarkus application:

```shell
mvn io.quarkus.platform:quarkus-maven-plugin:@QUARKUS_VERSION@:create \
  -DplatformVersion=@QUARKUS_VERSION@ \
  -DprojectGroupId=org.acme \
  -DprojectArtifactId=authorization-quickstart \
  -Dextensions=rest-jackson,config-yaml,oidc,elytron-security-common \
  -DnoCode
cd authorization-quickstart
```

Add the authorization-server dependency to `pom.xml`:

```xml
<dependency>
    <groupId>@EXTENSION_GROUP@</groupId>
    <artifactId>quarkus-authorization-server</artifactId>
    <version>@EXTENSION_VERSION@</version>
</dependency>
```

For an existing application, use the Quarkus `@QUARKUS_VERSION@` platform BOM and add the same dependencies:

| Dependency | Purpose |
| --- | --- |
| `@EXTENSION_GROUP@:quarkus-authorization-server:@EXTENSION_VERSION@` | Authorization endpoints, client registration, token issuance and default browser pages |
| `io.quarkus:quarkus-config-yaml` | Read `application.yml` |
| `io.quarkus:quarkus-oidc` | Validate access tokens at the resource API |
| `io.quarkus:quarkus-rest-jackson` | Implement the application's JSON resource endpoint |
| `io.quarkus:quarkus-elytron-security-common` | Hash and verify this demo user's password with `BcryptUtil` |

The Quarkus platform manages the `io.quarkus` dependency versions. Applications consume the authorization-server runtime artifact; Quarkus resolves its deployment artifact automatically.

## 2. Provide user authentication through CDI

The application owns its users. Create `src/main/java/org/acme/DemoIdentityProviders.java`:

<<< @/snippets/getting-started/DemoIdentityProviders.java

This demo has one user, **`alice` / `alice-password`**, with a username, password hash, roles and permissions. Replace the map with your user service when integrating your application.

Both providers share that user service:

- `UsernamePasswordAuthenticationRequest`: verify the password submitted to Quarkus Form.
- `TrustedAuthenticationRequest`: reload the user's identity on subsequent requests, after Quarkus Form has validated its encrypted login cookie.

They authenticate the authorization server's user. The resource server obtains its identity from the access token through `quarkus-oidc`; it does not call these password providers.

## 3. Configure the client, login and resource server

Create `src/main/resources/application.yml`. If the generated application has an empty `application.properties`, remove it; keep this tutorial's settings in one file.

<<< @/snippets/getting-started/application.yml

The two configuration groups have different responsibilities:

- **`quarkus.authorization-server`** serves the OAuth endpoints, registers `quickstart-client` in the default in-memory repository, and enables the built-in login page. `quarkus.http.auth.form.enabled` enables Quarkus Form authentication.
- **`quarkus.oidc`** validates Bearer tokens for the resource API. OIDC discovery is enabled on the authorization server so the resource server can discover its JWKS. The short connection timeout lets this single-process example start before its own HTTP listener is ready and reconnect when needed.

This is a confidential client: it authenticates at the token endpoint with HTTP Basic, using client ID **`quickstart-client`** and client secret **`quickstart-secret`**. The YAML already contains the bcrypt hash of that demo secret; copy it as shown. `require-proof-key: false` keeps PKCE out of this walkthrough. Consent for `message.read` is still required.

The map key `quickstart-client` is the client ID. The registered callback must exactly match the URI in the authorization and token requests. The client secret is used only by the terminal command, standing in for a backend OAuth client; do not put it in the callback page or frontend JavaScript.

The `/api/*` permission explicitly selects **Bearer** authentication. A browser login cookie alone cannot access the API. The resource server also checks that the token audience contains `quickstart-client`, the authorization server's default audience for this client.

For this local walkthrough, the defaults provide in-memory client, authorization and consent repositories and a temporary RSA signing key. No repository bean or PEM file is needed. Restarting the application loses authorizations and consent and changes the signing key.

## 4. Add a protected API and callback page

Create `src/main/java/org/acme/MessageResource.java`:

<<< @/snippets/getting-started/MessageResource.java

`quarkus-oidc` validates the token and maps its scopes to permissions. `@PermissionsAllowed("message.read")` then checks the permission required by this endpoint.

Create `src/main/resources/META-INF/resources/callback.html`:

<<< @/snippets/getting-started/callback.html

This page is only the tutorial's callback destination. The terminal will check `state` and exchange the authorization code. In an application with a backend, its OAuth client handles the callback and exchange.

## 5. Start the application

```shell
mvn quarkus:dev
```

Wait for `http://localhost:8080` to start. Because both servers share one process, you may initially see an `OIDC server is not available` warning: discovery reconnects on the first request after the HTTP listener starts. You can inspect the discovery document:

```shell
curl -sS http://localhost:8080/.well-known/openid-configuration
```

## 6. Sign in and obtain an access token {#login-and-token}

In a **second terminal**, generate a random `state` and the authorization URL. `state` binds the callback to the request you started. Keep this terminal open for the remaining commands:

<<< @/snippets/getting-started/authorize.sh{shell}

Open the printed URL in your browser:

1. Sign in as **`alice`** with password **`alice-password`**.
2. Select the **`message.read`** checkbox, then click **Approve**.
3. The browser redirects to `http://localhost:8080/callback.html?code=…&state=…`.
4. Copy the **complete callback URL** from the address bar.

Login authenticates the user; the callback contains an **authorization code**, not an access token. Exchange the code using the client ID and secret.

In the same terminal, first run the following command, paste the callback URL when `read` waits for input, and press Enter:

```shell
read -r QAS_CALLBACK
```

Then validate `state` and exchange the code using HTTP Basic client authentication:

<<< @/snippets/getting-started/exchange.sh{shell}

On success, `QAS_ACCESS_TOKEN` contains the access token. `curl -u` sends the client credentials in the HTTP Basic header. These credentials authenticate the OAuth client; `alice` / `alice-password` authenticates the user on the login page. The token response includes `token_type: Bearer` and `expires_in`; this client does not request a refresh token or ID Token.

An authorization code is short-lived and can only be used once. If it expires, is already used, or the state check fails, repeat this section to start a new authorization request. If you deny consent, the callback contains an OAuth error and the command stops before requesting a token.

## 7. Call the resource server

In the same terminal:

```shell
curl -sS -H "Authorization: Bearer $QAS_ACCESS_TOKEN" \
  http://localhost:8080/api/messages
```

Expected JSON, regardless of field order:

```json
{"subject":"alice","message":"Hello, OAuth!"}
```

Without a token, the API returns `401`. An authenticated token without the required `message.read` permission receives `403`.

The user's roles and permissions are not automatically copied into the token or intersected with client scopes. This example authorizes API access through the granted scope; add your own user-access policy where your application needs it. See [Identity and access](./identity-and-access).

## Continue with your application

- [Configuration reference](/reference/): client settings, default pages, endpoint paths and CDI replacements.
- [Storage and keys](./storage-and-keys): durable repositories, signing keys and the separate Quarkus Form session encryption key.
- [Tokens and resource servers](./tokens-and-resources): run the resource server separately, validate issuer and audience, and customize claims.
- [Authorization Code + PKCE](./authorization-code): continue with a public Vue client using PKCE, OIDC and logout. The [repository examples](https://github.com/flynndi/quarkus-authorization-server/tree/main/examples) are optional runnable references.
- [Client Credentials](./client-credentials): machine-to-machine access without user login.

Before deployment, use HTTPS and your public issuer and callback URLs, replace demo credentials, and configure persistent keys and storage. Separating the two servers does not change the flow: the resource server's `quarkus.oidc.auth-server-url` points to the authorization server.
