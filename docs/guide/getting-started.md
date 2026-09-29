# Getting Started

Run an authorization server and a resource API as **two separate Quarkus applications**. Sign in on the authorization server, let an OAuth client obtain an access token with **Authorization Code**, and use that token to call the API protected by **`quarkus-oidc`**.

The authorization server owns the users and authenticates them through Quarkus Form. The resource API trusts tokens from that server; it does not look up the user's password or use the server's login session. This works for a new system or one with an existing user service.

| Role | In this walkthrough | Responsibility |
| --- | --- | --- |
| Authorization server | `authorization-server`, port `8080` | User login, consent, client authentication and token issuance |
| Resource server | `resource-server`, port `8081` | Validate the access token and require `message.read` for `/api/messages` |
| OAuth client | Browser and terminal commands | Start authorization, receive a code, exchange it for a token and call the API |

The browser redirects between the authorization server and the callback page. The terminal sends the code to the authorization server's token endpoint, then sends the access token to the resource API. The resource application hosts a static callback helper so this walkthrough needs no frontend build or third server; it does not perform the token exchange.

You need **JDK 21**, **Maven 3.9+**, **curl 7.76+**, **Python 3**, and a browser. Keep ports `8080` and `8081` free and use `localhost` consistently. You do not need this repository's source or a database.

## 1. Create the authorization server

Create a working directory and the first application:

```shell
mkdir oauth-quickstart
cd oauth-quickstart
mvn io.quarkus.platform:quarkus-maven-plugin:@QUARKUS_VERSION@:create \
  -DplatformVersion=@QUARKUS_VERSION@ \
  -DprojectGroupId=org.acme \
  -DprojectArtifactId=authorization-server \
  -Dextensions=config-yaml,elytron-security-common \
  -DnoCode
cd authorization-server
```

Add the authorization-server dependency to the top-level `<dependencies>` section in this application's `pom.xml`:

```xml
<dependency>
    <groupId>@EXTENSION_GROUP@</groupId>
    <artifactId>quarkus-authorization-server</artifactId>
    <version>@EXTENSION_VERSION@</version>
</dependency>
```

For an existing application, use the Quarkus `@QUARKUS_VERSION@` platform BOM and add these dependencies:

| Dependency | Purpose |
| --- | --- |
| `@EXTENSION_GROUP@:quarkus-authorization-server:@EXTENSION_VERSION@` | Authorization endpoints, client registration, token issuance and default browser pages |
| `io.quarkus:quarkus-config-yaml` | Read `application.yml` |
| `io.quarkus:quarkus-elytron-security-common` | Verify this demo user's password with `BcryptUtil` |

The platform manages the `io.quarkus` dependency versions. Applications consume the authorization-server runtime artifact; Quarkus resolves its deployment artifact automatically. This application does not need `quarkus-oidc` or Quarkus REST to serve the authorization endpoints.

## 2. Provide user authentication through CDI

In **`authorization-server`**, create `src/main/java/org/acme/DemoIdentityProviders.java`:

<<< @/snippets/getting-started/DemoIdentityProviders.java

This demo has one user, **`alice` / `alice-password`**, with a username, password hash, roles and permissions. Replace the map with your user service when integrating your application.

Both providers share that user service:

- `UsernamePasswordAuthenticationRequest`: verify the password submitted to Quarkus Form.
- `TrustedAuthenticationRequest`: reload the user's identity on subsequent requests, after Quarkus Form has validated its encrypted login cookie.

These beans belong only to the authorization server. The resource server uses `quarkus-oidc` to establish an identity from the access token.

## 3. Configure the client and login

In **`authorization-server`**, create `src/main/resources/application.yml`. If the generated application has an empty `application.properties`, remove it.

<<< @/snippets/getting-started/authorization-server.yml

**`quarkus.authorization-server`** serves the OAuth endpoints, registers `quickstart-client` in the default in-memory repository, and enables the built-in login page. **`quarkus.http.auth.form.enabled`** enables Quarkus Form authentication. Enabling OIDC publishes discovery metadata so the separate resource server can discover the issuer and its JWKS.

This is a confidential client: it authenticates at the token endpoint with HTTP Basic, using client ID **`quickstart-client`** and client secret **`quickstart-secret`**. The YAML already contains the bcrypt hash of that demo secret; copy it as shown. `require-proof-key: false` keeps PKCE out of this walkthrough. Consent for `message.read` is still required.

The map key `quickstart-client` is the client ID. The registered callback on port **`8081`** must exactly match the URI in the authorization and token requests. The terminal stands in for a backend OAuth client; the client secret is used only for token exchange. Do not put it in the callback page or frontend JavaScript.

For this local walkthrough, the defaults provide in-memory client, authorization and consent repositories and a temporary RSA signing key. No repository bean or PEM file is needed. Restarting the authorization server loses authorizations and consent and changes the signing key.

## 4. Create the resource server

Return to the **`oauth-quickstart`** parent directory and create a second application alongside the first:

```shell
cd ..
mvn io.quarkus.platform:quarkus-maven-plugin:@QUARKUS_VERSION@:create \
  -DplatformVersion=@QUARKUS_VERSION@ \
  -DprojectGroupId=org.acme \
  -DprojectArtifactId=resource-server \
  -Dextensions=rest-jackson,config-yaml,oidc \
  -DnoCode
cd resource-server
```

This application uses `quarkus-rest-jackson` for its JSON API, `quarkus-config-yaml` for configuration and `quarkus-oidc` for Bearer token validation. It does not need the authorization-server dependency, the user authentication beans or a signing private key.

## 5. Configure the resource API and callback page

In **`resource-server`**, create `src/main/resources/application.yml`. Remove its empty `application.properties` if present.

<<< @/snippets/getting-started/resource-server.yml

The API listens on **`8081`**; `quarkus.oidc.auth-server-url` points to the authorization server on **`8080`**. `quarkus-oidc` discovers its public keys and validates the token's signature, issuer, expiry and audience. The audience must contain `quickstart-client`, the authorization server's default audience for this client.

The `/api/*` rule selects **Bearer** authentication. A Form login cookie alone cannot access the API. This resource server uses local JWT validation and does not send the user's password to the authorization server or call the token endpoint to authenticate each API request.

Create `src/main/java/org/acme/MessageResource.java` in **`resource-server`**:

<<< @/snippets/getting-started/MessageResource.java

`quarkus-oidc` maps the validated token's scopes to permissions. `@PermissionsAllowed("message.read")` checks the permission required by this endpoint.

Also in **`resource-server`**, create `src/main/resources/META-INF/resources/callback.html`:

<<< @/snippets/getting-started/callback.html

This publicly accessible static page is only the tutorial client's callback destination. The terminal checks `state` and exchanges the code. In your own application, register the actual OAuth client's callback; serving a callback page is not a resource-server requirement.

## 6. Start both applications

Open two terminals, each initially in **`oauth-quickstart`**. In the first, start the authorization server:

```shell
cd authorization-server
mvn quarkus:dev
```

Wait for `http://localhost:8080` to start. In the second terminal, check discovery, then start the resource server:

```shell
curl --fail-with-body -sS http://localhost:8080/.well-known/openid-configuration
cd resource-server
mvn quarkus:dev -Ddebug=5006
```

Wait for `http://localhost:8081` to start. The second debug port avoids a clash with the authorization server's dev-mode debugger. Start the authorization server first so the resource server can reach discovery during startup. If you restart the authorization server with a new temporary key, restart the resource server and obtain a new token for this walkthrough.

## 7. Sign in and obtain an access token {#login-and-token}

In a **third terminal**, generate a random `state` and the authorization URL. `state` binds the callback to the request you started. Keep this terminal open for the remaining commands:

<<< @/snippets/getting-started/authorize.sh{shell}

Open the printed URL in your browser:

1. Sign in on **`localhost:8080`** as **`alice`** with password **`alice-password`**.
2. Select the **`message.read`** checkbox, then click **Approve**.
3. The browser redirects to `http://localhost:8081/callback.html?code=…&state=…`.
4. Copy the **complete callback URL** from the address bar.

Login authenticates the user; the callback contains an **authorization code**, not an access token. Exchange the code at the authorization server on **`8080`**, using the client ID and secret.

In the same terminal, first run the following command, paste the callback URL when `read` waits for input, and press Enter:

```shell
read -r QAS_CALLBACK
```

Then validate `state` and exchange the code using HTTP Basic client authentication:

<<< @/snippets/getting-started/exchange.sh{shell}

On success, `QAS_ACCESS_TOKEN` contains the access token. `curl -u` sends the client credentials in the HTTP Basic header. These credentials authenticate the OAuth client; `alice` / `alice-password` authenticates the user on the login page. The token response includes `token_type: Bearer` and `expires_in`; this client does not request a refresh token or ID Token.

An authorization code is short-lived and can only be used once. If it expires, is already used, or the state check fails, repeat this section to start a new authorization request. If you deny consent, the callback contains an OAuth error and the command stops before requesting a token.

## 8. Call the resource server

In the same terminal, send the access token to the resource API on **`8081`**:

```shell
curl --fail-with-body -sS -H "Authorization: Bearer $QAS_ACCESS_TOKEN" \
  http://localhost:8081/api/messages
```

Expected JSON, regardless of field order:

```json
{"subject":"alice","message":"Hello, OAuth!"}
```

The resource API returns `401` without a token. You can check this separately:

```shell
curl -i http://localhost:8081/api/messages
```

An authenticated token without the required `message.read` permission receives `403`. The resource API makes this access decision independently of the authorization server's login session.

The user's roles and permissions are not automatically copied into the token or intersected with client scopes. This example authorizes API access through the granted scope; add your own user-access policy where your application needs it. See [Identity and access](./identity-and-access).

## Continue with your application

- [Configuration reference](/reference/): client settings, default pages, endpoint paths and CDI replacements.
- [Storage and keys](./storage-and-keys): durable repositories, signing keys and the separate Quarkus Form session encryption key.
- [Tokens and resource servers](./tokens-and-resources): issuer and audience validation, token representations and custom claims.
- [Authorization Code + PKCE](./authorization-code): continue with a public Vue client using PKCE, OIDC and logout. The [repository examples](https://github.com/flynndi/quarkus-authorization-server/tree/main/examples) are optional runnable references.
- [Client Credentials](./client-credentials): machine-to-machine access without user login.

Before deployment, use HTTPS and your public issuer and client callback URLs, replace demo credentials, and configure persistent keys and storage. The authorization server and resource API can run on different hosts; set the resource server's `quarkus.oidc.auth-server-url` to the authorization server's public issuer.
