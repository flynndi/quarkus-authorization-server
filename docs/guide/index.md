# Introduction

Quarkus Authorization Server is a Quarkus extension that runs an OAuth 2.0 authorization server in the application process, with optional OpenID Connect. It integrates through Quarkus CDI, HTTP Security, `SecurityIdentity`, Vert.x and build-time augmentation.

The coordinates are `@EXTENSION_GROUP@:quarkus-authorization-server:@EXTENSION_VERSION@`. These guides explain how to configure the extension and run the applications in this repository's `examples` directory.

## What it is for

Applications that need to issue access tokens, authenticate clients, and optionally authenticate a browser user who consents to scopes. The extension owns protocol endpoints, authorization records, token generation, and the default login/consent HTML. The application owns:

- The user model, plus `IdentityProvider` implementations for form passwords and cookie restoration
- Client and authorization storage (in-memory by default, or JDBC through CDI)
- Production issuer URL, signing keys and database migrations
- How a resource API interprets scopes, roles and claims in the token

User roles/permissions, client scopes and resource-server authorization are not automatically equivalent and do not inherit from each other.

## How it fits Quarkus

- Applications consume `runtime`; build-time wiring lives in `deployment`.
- Protocol routes are installed with `RouteBuildItem` and handled by Vert.x, not Quarkus REST.
- OAuth client authentication goes through `IdentityProviderManager` and continues as `SecurityIdentity`.
- Opting into the built-in login pages and Quarkus Form installs browser mechanism selection and overridable Form defaults; user authentication still uses the application's providers.
- Synchronous protocol work runs on a worker. HTTP adapters do not pass `RoutingContext` into domain services.
- A resource server that uses `quarkus-oidc` can discover the same issuer's metadata and JWKS.

Read the [architecture guide](./architecture) for module boundaries and the request chain. See [Protocol support](/reference/protocol-support) for implementation limits.

## Capabilities already implemented

| Capability | Behaviour |
| --- | --- |
| Authorization Code | S256 PKCE, consent, protocol checks before login; `prompt=none` when OIDC is on |
| Refresh Token | Scope can be narrowed; a public client does not receive a refresh token unless DPoP is used |
| Client Credentials | The client is the subject; only an access token is issued |
| Device Authorization | The user must confirm the device; existing consent does not auto-approve it |
| Token Exchange | Local active subject/actor tokens; no federation with an external issuer |
| Password | Password-based grant using the application's Quarkus user authentication |
| Tokens and metadata | JWT or reference tokens, JWKS, introspection, revocation, OAuth metadata |
| Client authentication | Basic, POST, `private_key_jwt`, `client_secret_jwt`, both mTLS methods, public `none` |
| OIDC | Discovery, UserInfo, RP-Initiated Logout with `id_token_hint` |
| DPoP | Supported by default and optional for clients; verifies proofs and binds tokens in supported grant flows |
| PAR / dynamic registration / multiple issuers | Configured as needed; metadata only advertises installed capabilities |

The supported capabilities and their boundaries are described below and in the protocol guides. Source, public SPI and tests are authoritative.

## What the application must provide

The shortest machine-client path registers a `client_credentials` client, sets an issuer and exposes a protected resource. The default key source can generate temporary signing keys for a local demo; durable keys are a deployment choice described in [Signing keys](/reference/signing).

A browser Code + PKCE path also needs user `IdentityProvider` beans and a frontend that acts as an OAuth client. Enable the built-in login integration with `quarkus.authorization-server.default-login-page-enabled=true` and `quarkus.http.auth.form.enabled=true`; it selects Form for the extension's browser endpoints. Login and consent stay on authorization-server pages, while the application keeps its resource API rules. See the [Code guide](./authorization-code) for configuration and customization.

Do not copy the `integration-tests` fixtures (public passwords, bundled PEMs, H2 schema bootstrap) into production. Those values exist for demonstration and verification only.

## Next

1. [Getting started](/guide/getting-started): add the dependency to your application, provide CDI user authentication, configure YAML, sign in and call a `quarkus-oidc` resource API.
2. [Reference](/reference/): where to look up configuration keys, endpoints and SPI.
3. [Playground](/playground/): try four OAuth flows against the Quarkus demo server, inspect tokens and call protected APIs. Offline PKCE, JWT and request tools remain available.

## Choose a guide

| Your task | Guide |
| --- | --- |
| Sign users in and call an API from a browser | [Authorization Code + PKCE](./authorization-code) |
| Call an API as a machine client | [Client Credentials](./client-credentials) |
| Explore device, refresh, exchange and password flows | [Other grants](./other-grants) |
| Connect a user store and distinguish scopes from permissions | [Identity and access](./identity-and-access) |
| Customize claims and verify resource requests | [Tokens and resource servers](./tokens-and-resources) |
| Persist authorization data and supply durable keys | [Storage and signing keys](./storage-and-keys) |
