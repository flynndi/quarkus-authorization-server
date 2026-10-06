# Authorization Code + PKCE

Use this flow when a browser application needs a user to sign in and authorize access to an API. The Vue application is a public OAuth client: it has a client ID and uses S256 PKCE, without a client secret.

## Run the example

[Getting Started](./getting-started) creates separate authorization-server and resource-server applications from dependencies and walks through login, Authorization Code with client-secret authentication, and a protected API. This page adds PKCE for a public client through the optional [Vue example](https://github.com/flynndi/quarkus-authorization-server/tree/main/examples/authorization-code). The Vue example hosts the authorization server and resource API in one backend for convenience. Start it from the repository root:

```shell
./gradlew :examples:authorization-code:quarkusDev --no-parallel
```

In another terminal, start the frontend:

```shell
cd examples/authorization-code/frontend
npm ci
npm run dev
```

Open `http://localhost:5173/` and sign in as `resource-owner` / `resource-owner-password`. The client ID, callback and account below belong to that example, not the quickstart application.

| Setting | Example value |
| --- | --- |
| Issuer | `http://localhost:8080` |
| Client ID | `authorization-code-public-client` |
| Client authentication | `none` |
| Grant | `authorization_code` |
| Redirect URI | `http://localhost:5173/callback` |
| Post-logout redirect | `http://localhost:5173/` |
| Requested scopes | `openid profile message.read` |

The client is registered by [`AuthorizationServerPersistence`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/src/main/java/io/quarkiverse/authorization/server/example/authorizationcode/authorizationserver/config/AuthorizationServerPersistence.java). It explicitly requires PKCE and consent. The example uses OIDC for discovery, UserInfo and logout.

## Client and resource-server roles {#client-and-resource-server-roles}

The Vue application is the OIDC Relying Party (RP). Its `oidc-client-ts` library starts Authorization Code + PKCE, processes the callback and the returned ID Token, and keeps the client-side user state. It sends the **access token** to the API.

The backend's `quarkus-oidc` configuration uses `application-type=service` for Bearer validation. It does not initiate the browser's login flow in this example. The extension supplies the AS/OP endpoints, and Quarkus Form authenticates the user on the authorization server.

A Quarkus server-side client can instead use the upstream [`quarkus-oidc` web-app mode](https://quarkus.io/guides/security-oidc-code-flow-authentication/) to drive OIDC login. This Vue example does not verify that separate integration. See [the introduction](./index#oidc-roles) for the distinction between client login and resource-server token validation.

## Follow one request

1. `oidc-client-ts` creates state and a PKCE verifier, then navigates to the authorization endpoint with an S256 challenge.
2. The extension validates the authorization request before asking Quarkus Form to challenge an unauthenticated user.
3. The default login page posts the credentials to `/j_security_check`. Quarkus authenticates the user, sets its encrypted Form cookie and resumes the original authorization URL.
4. The extension shows consent when required. The user approves scopes or denies the request on the authorization server.
5. The browser returns to the registered callback with a code and state, or an OAuth error. The client validates state and exchanges the code plus verifier at the token endpoint.
6. Vue calls `/api/messages` with the access token. `quarkus-oidc` verifies that token; the API requires `message.read`.

The client implementation is in [`client.js`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/frontend/src/client.js). Tokens remain in memory; only the temporary authorization transaction uses `sessionStorage`.

## Keep browser login and API authentication separate

Enable the built-in pages and Quarkus Form. The extension selects Form for its browser endpoints; the application keeps control of API authentication:

Only `default-login-page-enabled` and `quarkus.http.auth.form.enabled` enable browser login. The OIDC switch and resource permission below additionally enable this example's OIDC flow and isolate its Bearer API.

```yaml
quarkus:
  authorization-server:
    default-login-page-enabled: true
    oidc:
      enabled: true
  http:
    auth:
      form:
        enabled: true
      permission:
        resources:
          paths: /api/*
          policy: authenticated
          auth-mechanism: Bearer
```

The defaults serve `/login.html` and `/error.html`, posting to `/j_security_check`. No extra login or authorization permission entries are required. The same integration selects Form for device verification and, when OIDC is enabled, logout; it does not make those endpoints public or change their protocol checks.

To retain the example's `/auth/login` URL, add these properties while keeping the built-in pages enabled:

```properties
quarkus.http.auth.form.login-page=/auth/login
quarkus.http.auth.form.error-page=/auth/login?error=true
```

With the built-in pages enabled, Form defaults to an HttpOnly cookie with SameSite=Lax and a landing page that follows `login-page`. Explicit Quarkus configuration overrides these defaults. These settings apply to the host's shared Form mechanism, not a separate OAuth cookie. See [browser login configuration](/reference/configuration#browser-login) for conflict rules and custom login integration.

This is a configuration excerpt, not a complete application. See the [full example](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/src/main/resources/application.yml) for issuer, keys, cookie lifetime, CORS and the resource server. The application still supplies its registered client and [user IdentityProviders](./identity-and-access). Fixed signing PEMs are optional for a local demo: with no `signing` configuration, the default key source generates a temporary RSA key. Durable deployments provide their own keys and Form session encryption key; these are separate responsibilities.

The extension selects Form while allowing initial authorization requests to reach protocol validation. Consent POST still requires an authenticated identity and valid state. An application rule that requires authentication for every authorize request would challenge before protocol validation, including OIDC `prompt=none`.

## Customize browser login {#customize-browser-login}

Use the built-in defaults or configure Quarkus Form to match your application:

- **Default pages and cookies:** the two login switches are enough to select Form for the browser endpoints. The default POST location, HttpOnly, SameSite and landing-page values do not need to be repeated in application configuration.
- **Custom settings:** configure page paths, cookie lifetime, landing page and `quarkus.http.auth.session.encryption-key` as needed. Explicit values override the defaults.
- **HTTP permissions:** configure the resource API's Bearer rule and application-specific checks. Browser mechanism selection is supplied by the extension. If startup reports an `auth-mechanism` conflict, inspect the named exact-path or shared permission and select Form for the built-in integration.
- **Application-owned login:** disable `default-login-page-enabled` and provide your pages, authentication mechanism selection and desired Form settings.

Changing the page URL does not require a new page bean. To replace the login implementation, supply your own integration; disabling the built-in mode also removes its mechanism selection and three additional defaults. Replacing consent or device-confirmation rendering through their page SPIs is independent of that switch.

## Adapt it to your application

- Implement user lookup and authentication as described in [identity and access](./identity-and-access). Login and consent remain on the authorization server; the frontend handles the OAuth callback.
- Register the exact frontend callback and logout URLs. In this example they are constants in the client registration; changing only `demo.frontend-url` does not update them.
- Set frontend `VITE_AUTHORITY` and backend `issuer` to the same public authorization-server URL. Set `demo.frontend-url` to the frontend origin for CORS.
- Use HTTPS for a public deployment. Browser API requests carry the access token, without cross-origin Form cookies. Changing hostnames also requires checking cookie and redirect settings.

## Refresh and logout

This particular demo client only registers the authorization-code grant. The Vue client disables automatic silent renewal and loses its in-memory tokens on a page reload; it then starts authorization again.

More generally, this server issues refresh tokens to public clients only when the supported DPoP flow and refresh grant are configured. A confidential client can use the ordinary refresh flow. Registering `refresh_token` alone does not give this public Bearer client a refresh token.

OIDC logout uses the ID Token as `id_token_hint`, clears the browser session and returns to the registered logout URL. It does not automatically revoke existing access tokens or delete historical consent. See [other grants](./other-grants) and [tokens and resource servers](./tokens-and-resources).

Exact initial-request, consent and PAR parameters are in [OAuth endpoints](/reference/endpoints); UserInfo and logout are in [OIDC and registration](/reference/oidc-and-registration).
