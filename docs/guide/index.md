# Introduction

Quarkus Authorization Server is a Quarkus extension for building an OAuth 2.0 authorization service, with optional OpenID Connect. It is intended for **new or existing Quarkus systems that manage their own users and authentication and need to authorize other applications to access their APIs**.

For example, a system has a user service and a messages API. Another application wants to read a user's messages with their permission. The user signs in on the authorization server and approves `message.read`. The client application receives an access token and presents it to the messages API. It does not need the user's password, direct access to the user database or the authorization server's login cookie.

## Login, authorization and API access

Quarkus Form authentication can handle local username/password login. The extension uses that login to establish who the user is, then provides the OAuth endpoints, client authentication, consent and token issuance that client applications need. If an application only needs its own local login, Form authentication can be enough.

| Role | What it does |
| --- | --- |
| Authorization server | Uses the application's user authentication, checks the OAuth client and requested access, and issues tokens |
| OAuth client | Redirects the user to sign in and authorize access, handles the callback, obtains an access token and calls the API |
| Resource API | Uses `quarkus-oidc` to validate the access token and enforces its own access rules |

With OpenID Connect enabled, client applications can also use the authorization server as their OpenID Provider for user sign-in. The extension implements the AS/OP side; a client application uses an OAuth/OIDC client library to integrate with it.

The [quickstart](./getting-started) runs the authorization server and resource API as **separate applications**, connected through issuer discovery, public keys and access tokens. The resource API does not need the authorization-server extension or the user's password store. The extension runs inside the Quarkus application that hosts it, so you can build a dedicated authorization service or add it to an application; the protocol roles remain distinct.

## What your application provides

The extension owns protocol endpoints, authorization records, token generation and default login/consent pages. Your application owns:

- The user model and authentication; the Form-based quickstart connects these through `IdentityProvider` beans
- Client registrations and storage for clients, authorizations and consent (in-memory by default, or JDBC through CDI)
- The issuer URL, durable signing keys and database migrations for deployment
- The resource API's interpretation of scopes, roles and claims

User roles/permissions, client scopes and resource-server authorization are not automatically equivalent and do not inherit from each other. The extension supplies authorization-server building blocks, rather than a complete user-management product.

Start by adding `@EXTENSION_GROUP@:quarkus-authorization-server:@EXTENSION_VERSION@` to the authorization-server application. The [quickstart](./getting-started) walks through the dependencies, user beans, two applications' YAML configuration and a complete code-to-token-to-API flow; no repository checkout is needed.

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

## Next

1. [Getting started](/guide/getting-started): run a separate authorization server and resource API, obtain a token through Authorization Code, and call the API.
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
