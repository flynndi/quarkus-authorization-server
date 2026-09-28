# Protocol support and boundaries

This is the scope of the current source, not a claim of complete Spring Authorization Server compatibility or a feature roadmap. Detailed requests are in [OAuth endpoints](./endpoints) and [OIDC and registration](./oidc-and-registration); settings are in [configuration](./configuration).

## Grants and authentication {#grants}

| Area | Implemented boundary |
| --- | --- |
| Code + PKCE | Code response; S256 PKCE, pre-login protocol validation, pending consent and user/client binding. No implicit/hybrid response implementation. |
| Client Credentials | Client-only access token; no refresh token. Requested scopes are checked against the client, not a human user's roles. |
| Refresh | Existing authorization and client required; scope can narrow. Public-client restrictions are described below. |
| Device | Issue device/user codes, browser confirmation, token polling. No built-in poll throttling or `slow_down`. |
| Password | Project-specific compatibility grant using Quarkus user authentication; not the recommended browser login flow, and not a claim of SAS grant parity. |
| Token Exchange | Active locally stored subject/actor tokens, user subject and delegation checks, output token generation. No general external-token trust federation. |
| Client authentication | Basic, POST, private-key JWT, secret JWT, mTLS/self-signed mTLS and public identification. TLS client authentication does not add certificate-bound access tokens. |

The dispatch and checks are defined by [OAuth2TokenEndpointHandler], [TokenExchangeGrant] and the [client authentication reference](./clients).

## Tokens, refresh and DPoP {#tokens}

The generator supports signed JWT and opaque/reference access tokens. ID Tokens are JWTs. A token's scope does not automatically include user roles: map claims with CDI and enforce permissions at the resource server.

Public Code clients may receive Bearer access tokens without DPoP, but do not receive refresh tokens through that unbound flow. DPoP-bound public Code flows can issue and refresh using the same proof key. Confidential clients may use ordinary Bearer refresh when their grants permit it; bound refresh still requires the matching key. Rotation/reuse follows `TokenSettings`; this is not a promise of token-family replay detection or atomic concurrent rotation. See [OAuth2RefreshTokenGenerator] and [RefreshTokenGrant].

DPoP is optional per supported request, with no global enable switch. Proof validation, key binding, local replay protection and algorithm discovery are implemented for Code, Refresh, Client Credentials, Device and Token Exchange output. UserInfo accepts bound tokens with a resource proof. Password rejects DPoP. Token Exchange does not validate/inherit DPoP binding on its inputs. Server nonce issuance and a built-in distributed replay store are absent. See [DPoP configuration](./dpop).

The `quarkus-oidc` resource-server example verifies resource-side interoperability; the authorization server does not configure another application's token validation. Offline JWT validation cannot instantly reflect database revocation. Existing interoperability fixtures are in the [integration-test sources](https://github.com/flynndi/quarkus-authorization-server/tree/main/integration-tests).

## Browser, OIDC and PAR {#browser-protocols}

| Area | Implemented boundary |
| --- | --- |
| Browser interaction | Quarkus HTTP authentication, optional default Form login page, replaceable consent/device pages. No built-in SPA interaction-context API or managed user database. |
| `prompt=none` | Validate before login; return `login_required` / `consent_required` when silent completion is impossible. Not a complete `prompt=login`, account-selection or reauthentication system. |
| OIDC | Code-flow ID Tokens, discovery, JSON UserInfo, hint-based RP-Initiated Logout, optional protected registration. No signed/encrypted UserInfo or front/back-channel logout. |
| PAR | Optional authenticated push, five-minute references, stored request authoritative, ordinary authorization still allowed. No JAR or mandatory-PAR client setting. |
| Dynamic registration | Separate OAuth and OIDC contracts; open registration only for OAuth. Explicit scope policy required; limited management reads only for OIDC. No full client CRUD API. |

Application HTTP policies can prevent the authorize endpoint from running its anonymous prevalidation. Follow the [Code guide](/guide/authorization-code) when selecting the Form mechanism and protecting APIs; placing a blanket `authenticated` policy in front of authorize changes the `prompt=none` behavior.

## Persistence, transactions and multiple issuers {#storage}

Three in-memory stores are supplied by default; JDBC implementations are available through CDI. Schema creation/migration and durable client provisioning belong to the application. Persisted identity is an authorization-time snapshot, not a live login session or a serialization of arbitrary credentials/permission checkers.

JDBC writes use an already-enlisted Agroal/JTA transaction when present, otherwise a local transaction per write. The extension does not begin a whole-grant or whole-registration transaction. Registering a client, storing a registration token and consuming an initial token are separate operations by default. Concurrent single-use code/refresh/PAR consumption is not guaranteed atomic. `ProtocolExecutor` provides a worker/request-context boundary, not transaction demarcation. See [Storage and signing keys](/guide/storage-and-keys) and [JdbcTransactionSupport].

Multiple issuers use a finite configured tenant set with explicit repositories and keys. Endpoint suffixes, protocol switches, TLS/DPoP settings and application policy beans are shared. Form login is shared while OIDC session identifiers are issuer-derived. This is not dynamic tenant provisioning or automatic database row isolation. The registry checks bundle selection and repository-object separation, not the database schema. See [AuthorizationServerTenantRegistry].

## Verification scope {#verification}

Source links are pinned to the commit audited for this page. Existing Java/JVM/native results have their own scope and date; editing or building these pages does not rerun them. The [Playground](/playground/) separately reports what is actually connected to an online backend. Capability documentation does not make an unconnected demo live.

[AuthorizationServerTenantRegistry]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/tenant/AuthorizationServerTenantRegistry.java
[JdbcTransactionSupport]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/jdbc/JdbcTransactionSupport.java
[OAuth2RefreshTokenGenerator]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/token/OAuth2RefreshTokenGenerator.java
[OAuth2TokenEndpointHandler]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/web/OAuth2TokenEndpointHandler.java
[RefreshTokenGrant]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/refreshtoken/RefreshTokenGrant.java
[TokenExchangeGrant]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/tokenexchange/TokenExchangeGrant.java
