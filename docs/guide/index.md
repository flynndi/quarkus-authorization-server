# Introduction

**Experimental · Community-maintained**

OAuth2 and OpenID Connect Server Extension provides building blocks for OAuth 2.0 authorization servers, with optional OpenID Connect. It is maintained by community contributors, not by the Quarkus project or team. Development and security review are ongoing.

## Who this is for

This extension is intended for **experienced teams that choose to build and maintain their own authorization service**, for a new or existing system. Those teams manage their users and authentication, need to authorize client applications, and accept responsibility for evaluating protocol behavior, reviewing security and operating the service.

For an application that simply needs user sign-in or API protection, start with an established OAuth/OIDC provider and Quarkus Security. Building an authorization server is a separate engineering and maintenance commitment.

For example, a system has a user service and a messages API. Another application wants to read a user's messages with their permission. The user signs in on the authorization server and approves `message.read`. The client application receives an access token and presents it to the messages API. It does not need the user's password, direct access to the user database or the authorization server's login cookie.

## Login, authorization and API access

Quarkus Form authentication handles the user's local login at the authorization server in the examples. The extension uses that identity to process authorization requests, obtain consent and issue tokens. Form login alone does not grant a different client application access to the API.

| Use case | Flow | What the client receives |
| --- | --- | --- |
| An application accesses an API on its own behalf | Client Credentials | An access token representing the client; no user login |
| An application accesses an API with a user's permission | Authorization Code | An access token for the authorized access |
| A user signs in to a client application through an OpenID Provider | OIDC Authorization Code with `openid` | An ID Token describing the user's authentication, plus an access token |

API calls carry the **access token**. The **ID Token** describes the user's authentication to the OIDC client and is not the credential for the resource API.

## Where `quarkus-oidc` fits {#oidc-roles}

The extension implements the authorization-server / OpenID Provider (AS/OP) side. OAuth/OIDC clients and resource servers have separate responsibilities:

| Role | Implementation in the current examples |
| --- | --- |
| Authorization server / OpenID Provider | This extension handles protocol endpoints and token issuance; the application supplies user authentication |
| OAuth/OIDC client (RP for OIDC sign-in) | The quickstart uses a browser and terminal commands for OAuth; the Vue example uses `oidc-client-ts` for OIDC Authorization Code + PKCE |
| Resource API | `quarkus-oidc` with `application-type=service` verifies Bearer access tokens; the API enforces its access rules |

`quarkus-oidc` also supports `application-type=web-app`, where it acts as an OIDC client and drives the authorization code login flow. That is a separate role from Bearer validation. The current Vue example delegates login to `oidc-client-ts`; it does not exercise the Quarkus `web-app` integration. See the [Quarkus code flow guide](https://quarkus.io/guides/security-oidc-code-flow-authentication/) and the [example's role breakdown](./authorization-code#client-and-resource-server-roles).

The authorization-server application does not need `quarkus-oidc` to provide AS/OP endpoints. Resource APIs must validate tokens; `quarkus-oidc` is the implementation used in these Quarkus examples. The protocols also allow clients and resource servers written with other compatible libraries.

The [quickstart](./getting-started) runs the authorization server and resource API as **separate applications**, connected through issuer discovery, public keys and access tokens. Build and operate the authorization server as its own service; the resource API does not need the extension or the user's password store. The extension runs inside the Quarkus application that hosts that authorization service.

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
