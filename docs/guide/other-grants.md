# Other grants

Start with [Authorization Code + PKCE](./authorization-code) for browser clients and [Client Credentials](./client-credentials) for machine clients. The extension also implements the flows below. A registered client's `authorization-grant-types` determines which grants it may use.

## Device Authorization

A device requests a device code and user code. A person opens the verification URL on a browser, signs in and approves the request. The device polls the token endpoint at the returned interval, then uses the access token to call the API.

```shell
./gradlew :examples:device-authorization:quarkusDev --no-parallel
```

The [device example](https://github.com/flynndi/quarkus-authorization-server/tree/main/examples/device-authorization) registers the client is `public-device`; the demo user is `resource-owner` / `resource-owner-password`. The token grant is `urn:ietf:params:oauth:grant-type:device_code`.

The browser confirmation uses the same [built-in login integration](/reference/configuration#browser-login) as Authorization Code. Enable the default pages and Quarkus Form; the extension selects Form for verification GET/POST while keeping the authenticated-user requirement. No separate device-verification mechanism rule is needed. The device authorization and token requests still use OAuth client authentication.

Before approval, polling returns `authorization_pending`; polling too quickly can return `slow_down`. A verification GET or a user's previous consent does not approve a new device request. The user must explicitly confirm it.

## Refresh Token

Refresh continues an existing authorization. The client must be registered for `refresh_token`, and the authorization must contain an active refresh token belonging to that client. A requested scope can narrow the original authorization; it cannot expand it.

The default reuses refresh tokens. Set the client's `reuse-refresh-tokens=false` to rotate them; a successfully replaced token subsequently fails with `invalid_grant`. Public clients require an existing DPoP key binding and the matching proof. Confidential clients may use ordinary refresh authentication.

This is not a separate user login. The service uses the authorization's saved identity, so it does not automatically reload user roles. See [`RefreshTokenGrant`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/refreshtoken/RefreshTokenGrant.java) and [identity and access](./identity-and-access).

## Token Exchange

Token Exchange uses `urn:ietf:params:oauth:grant-type:token-exchange` to request a new access token from a subject token, optionally with an actor token for delegation. The current service looks up active tokens in this issuer's authorization store; it is not an external-issuer federation gateway.

The implementation supports JWT/reference representations and actor-chain claims. DPoP, when used here, binds the output token; it does not validate or inherit input subject/actor DPoP bindings. It does not issue a refresh token.

The advanced fixture and HTTP tests live in [`integration-tests/token-exchange`](https://github.com/flynndi/quarkus-authorization-server/tree/main/integration-tests/token-exchange); protocol logic is in [`TokenExchangeGrant`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/tokenexchange/TokenExchangeGrant.java). Use the fixture to study the contract, not as a ready-to-publish demo backend with its test-only endpoints.

## Password

This project additionally implements `grant_type=password`. The client submits the user's password to the token endpoint, and the application supplies an `IdentityProvider<UsernamePasswordAuthenticationRequest>`.

```shell
./gradlew :examples:password-grant:quarkusDev --no-parallel
```

The [Password example sources](https://github.com/flynndi/quarkus-authorization-server/tree/main/examples/password-grant) contain the client registration, demo users and resource API. This flow has no browser Form-cookie restoration step and therefore does not need a Trusted provider just for the grant. Password does not support DPoP; requests carrying a DPoP header are rejected. For the browser application documented on this site, use Code + PKCE.

## Where to run them

The four simple applications are under `examples`; protocol edge cases, Token Exchange and advanced interoperability are under `integration-tests`. Stop one example before starting another on port 8080.

The [Playground](/playground/) will connect to a separately supplied Quarkus demo backend covering all supported grants. Until that connection is available, use the local examples; this static site does not itself issue tokens.

Look up the complete grant parameter table in [OAuth endpoints](/reference/endpoints#token-grants) and the current limits in [Protocol support](/reference/protocol-support).
