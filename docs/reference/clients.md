# Registered clients

Prefix: `quarkus.authorization-server.clients."<client-id>"`. All properties on this page are **`RUN_TIME`**: configure them at application startup; changing them does not require a rebuild and does not update an already running repository.

The Map key is the OAuth `client_id`. There are no configured clients by default. Each entry seeds the default `InMemoryRegisteredClientRepository`. An application CDI `RegisteredClientRepository` **replaces this repository completely**; `clients.*` is not imported into or merged with it. Multi-issuer mode uses tenant repositories and rejects global `clients.*` configuration.

Sources: [RegisteredClientConfig][config], [RegisteredClientRepositoryProducer][producer] and [RegisteredClient.Builder][client]. Tables show the effective values produced by this adapter, including Builder defaults for omitted optional properties.

## Identity and credentials {#identity}

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Property | Type / default | Requirement or behavior |
| --- | --- | --- |
| `id` | `String` · Map key | Internal repository ID; must not be blank. Distinct from `client_id`. |
| `client-name` | `String` · internal `id` | Display name. Omitted or blank values fall back to `id`, which itself defaults to the Map key. |
| `client-id-issued-at` | `Instant` · unset | ISO-8601 instant, for example `2026-01-01T00:00:00Z`. No automatic creation timestamp. |
| `client-secret` | `String` · unset | Needed for Basic, POST and HMAC authentication. Representation depends on the method; see [Authentication methods](#authentication). |
| `client-secret-expires-at` | `Instant` · unset | ISO-8601 instant. Basic/POST/HMAC reject an expired secret; omission means no configured expiration. |
| `client-authentication-methods` | `Set<String>` · `client_secret_basic` | Explicitly register the methods the client uses. See the method table below. |

</div>

### Authentication methods {#authentication}

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Method | Required registration material |
| --- | --- |
| `client_secret_basic`, `client_secret_post` | A bcrypt hash in `client-secret` with the default `ClientSecretVerifier`. The client presents the original secret. |
| `client_secret_jwt` | The raw UTF-8 shared secret in `client-secret` and an explicit HS256, HS384 or HS512 assertion algorithm. A bcrypt hash cannot replace the HMAC key. |
| `private_key_jwt` | `jwk-set-url` and an explicit RS/PS/ES assertion algorithm; no client secret. |
| `tls_client_auth` | `x509-certificate-subject-dn` plus TLS certificate validation by the host application; no client secret. |
| `self_signed_tls_client_auth` | `jwk-set-url` whose relevant JWK includes `x5c`; no client secret. |
| `none` | Public client; no client secret. Authorization Code exchange still requires PKCE. |

</div>

With the default bcrypt verifier, use separate clients for Basic/POST and `client_secret_jwt` because their stored secret representations differ. Config loading does not encode a plaintext secret for you. mTLS uses the actual TLS peer certificate, not a forwarded HTTP header; the host application must configure TLS.

These requirements are enforced by the authentication path, not all by config mapping at startup. Successfully loading a client entry does not prove it can authenticate.

Sources: [BcryptClientSecretVerifier][secret-verifier], [JwtClientAssertionVerifier][assertion-verifier] and [X509ClientCertificateAuthenticationProvider][x509-provider].

## Grants, redirects and scopes {#grants}

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Property | Type / default | Requirement or behavior |
| --- | --- | --- |
| `authorization-grant-types` | `Set<String>` · required | Must be nonempty. Built-in values are listed below; a custom value does not install a `GrantHandler`. |
| `redirect-uris` | `Set<String>` · empty | Required for `authorization_code`. Registration rejects invalid URI syntax and fragments. Authorization requests apply redirect matching, including loopback port rules. |
| `post-logout-redirect-uris` | `Set<String>` · empty | Optional. Registration rejects invalid URI syntax and fragments; Logout requires an exact registered match. |
| `scopes` | `Set<String>` · empty | Register allowed scope values, not user roles. Characters follow OAuth scope-token syntax: printable ASCII excluding space, double quote and backslash. |

</div>

Built-in grant values: `authorization_code`, `client_credentials`, `refresh_token`, `password`, `urn:ietf:params:oauth:grant-type:device_code` and `urn:ietf:params:oauth:grant-type:token-exchange`. See [Other grants](/guide/other-grants) for their usage boundaries. Registering `refresh_token` does not guarantee issuance in every flow; ordinary public Bearer Authorization Code clients do not receive a refresh token.

The properties above are for static/configured registrations. Dynamic registration has its own parsers, validators and allowed metadata; it is not a JSON mirror of this table.

## ClientSettings mapping {#client-settings}

Source: [ClientSettings][client-settings], applied by [RegisteredClientRepositoryProducer][producer]. All entries below retain the same client prefix and `RUN_TIME` phase.

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Property → Builder method | Type / effective default | Constraint or use |
| --- | --- | --- |
| `require-proof-key` → `requireProofKey(...)` | boolean · `true` | Requires S256 PKCE. A confidential client can set `false`; a public Code exchange still requires PKCE. A supplied challenge must use S256. |
| `require-authorization-consent` → `requireAuthorizationConsent(...)` | boolean · `false`; public Code client: `true` | Used by consent policy. `true` does not force a page for scopes already consented to. See default inference below. |
| `jwk-set-url` → `jwkSetUrl(...)` | `String` · unset | Required for `private_key_jwt` and `self_signed_tls_client_auth`. HTTPS URL with a host, no user info or fragment; subject to the [outbound destination policy](#client-jwks). Publishes the **client's** keys. |
| `x509-certificate-subject-dn` → `x509CertificateSubjectDN(...)` | `String` · unset | Required for `tls_client_auth`; nonblank DN parsed and compared using `X500Principal`. |
| `token-endpoint-authentication-signing-algorithm` → `tokenEndpointAuthenticationSigningAlgorithm(...)` | `String` → `JwsAlgorithm` · unset | Required for JWT assertion clients: RS256/384/512, PS256/384/512, ES256/384/512 for `private_key_jwt`; HS256/384/512 for `client_secret_jwt`. Unknown names are rejected. |

</div>

`ClientSettings.builder()` itself defaults to PKCE `true` and consent `false`. When no `ClientSettings` is explicitly provided, `RegisteredClient.Builder` infers consent `true` for a client with `authorization_code` and **exactly one** authentication method, `none`. Configured clients preserve this inference before applying explicit overrides. Supplying your own `ClientSettings` means you own those values; it does not repeat that inference.

`ClientSettings.withSettings(map)` copies existing settings rather than adding Builder defaults. Use it to adapt a complete settings object, not as a shortcut for default initialization. See [PkceVerifier][pkce] for the independent public-client PKCE requirement and [ClientJwkSetCache][jwks] for URL validation.

## Outbound client JWKS {#client-jwks}

The HTTPS requirement applies to downloading **client** verification keys. It does not change the authorization server's HTTP listener or issuer configuration; local authorization endpoints can still use HTTP.

JWKS downloads use Vert.x HTTP Client. Every download or refresh resolves the hostname, rejects non-public DNS answers by default, and connects to the checked IP while retaining the original host for TLS verification. Redirects are rejected. The request timeout is 15 seconds and the response size limit is 512 KiB. Both `private_key_jwt` and `self_signed_tls_client_auth` use this transport, including clients supplied directly by an application repository.

Outbound requests include `Cache-Control: no-cache` so proxies revalidate cached keys, including when an unknown `kid` triggers a refresh. The local jose4j key cache still uses the response cache lifetime. If the waiting worker is interrupted or times out, the request is cancelled; a connection acquired afterwards cannot send that cancelled request.

OIDC registration rejects non-HTTPS URLs and prohibited literal/localhost destinations even when the application replaces its registration validator. Hostnames are resolved when keys are actually downloaded; registration itself does not fetch keys. These mandatory checks implement the [OIDC registration HTTPS requirement](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata) and constrain outbound access.

For an intentionally private JWKS endpoint, configure its exact HTTPS origin (host and port). The exception applies only to that origin, not subdomains or other ports. HTTPS and certificate/hostname verification still apply. To trust a private CA, select a named Quarkus TLS configuration:

```yaml
quarkus:
  authorization-server:
    client-jwks:
      allowed-private-origins:
        - https://keys.internal.example:8443
      tls-configuration-name: client-jwks
  tls:
    client-jwks:
      trust-store:
        pem:
          certs: client-jwks-ca.pem
```

Both settings are runtime configuration and apply to all authorization-server tenants. `allowed-private-origins` is empty by default; `tls-configuration-name` is unset and uses system trust by default. Wildcards, HTTP origins, paths other than `/`, and queries are not accepted in the origin list. The named TLS configuration supplies trust and optional client credentials. The JWKS client is initialized with Quarkus `@Startup`, without downloading keys. Selecting a TLS configuration with `trust-all=true` fails startup, independently of whether an authentication request occurs; configure a trusted CA instead. JWKS downloads always verify hostnames, even if the named configuration disables hostname verification.

## TokenSettings mapping {#token-settings}

Source: [TokenSettings][token-settings], applied by [RegisteredClientRepositoryProducer][producer]. Defaults come from `TokenSettings.builder()`, not `@WithDefault` on individual client properties.

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Property → Builder method | Type / effective default | Constraint or use |
| --- | --- | --- |
| `authorization-code-time-to-live` → `authorizationCodeTimeToLive(...)` | `Duration` · `PT5M` | At least 1 second. Authorization code lifetime. |
| `access-token-time-to-live` → `accessTokenTimeToLive(...)` | `Duration` · `PT5M` | At least 1 second. Applies to JWT and opaque access tokens. |
| `device-code-time-to-live` → `deviceCodeTimeToLive(...)` | `Duration` · `PT5M` | At least 1 second. Shared by device code and user code. |
| `refresh-token-time-to-live` → `refreshTokenTimeToLive(...)` | `Duration` · `PT1H` | At least 1 second. Applies when a refresh token is issued. |
| `access-token-format` → `accessTokenFormat(...)` | `OAuth2TokenFormat` · `self-contained` | Default generator supports `self-contained` (JWT) and `reference` (opaque, queried through introspection). |
| `reuse-refresh-tokens` → `reuseRefreshTokens(...)` | boolean · `true` | `false` replaces the refresh token on successful refresh; the old value subsequently returns `invalid_grant`. This does not promise atomic concurrent consumption. |
| `id-token-signature-algorithm` → `idTokenSignatureAlgorithm(...)` | `SignatureAlgorithm` · `RS256` | RS256/384/512, PS256/384/512 or ES256/384/512. Requires a signing private key for that algorithm. Changes ID Token signing only. |

</div>

TTL setters validate `Duration.getSeconds() > 0`; a positive duration shorter than one second is rejected. Use explicit durations such as `PT5M` or `PT1H`. `TokenSettings.withSettings(map)` preserves a supplied map instead of initializing defaults.

`OAuth2TokenFormat` is a value object, not an enum restricted to the two built-in formats. A custom string still needs a compatible generator; merely accepting a configuration value does not implement a token format. ID Token TTL has no client configuration property; the default [JwtGenerator][jwt-generator] currently uses 30 minutes.

## Minimal examples {#examples}

A machine client with default Basic authentication; the environment variable contains a bcrypt hash:

```properties
quarkus.authorization-server.clients.machine.client-secret=${MACHINE_CLIENT_SECRET_BCRYPT}
quarkus.authorization-server.clients.machine.authorization-grant-types=client_credentials
quarkus.authorization-server.clients.machine.scopes=message.read
```

A public browser client using inferred PKCE and consent defaults:

```properties
quarkus.authorization-server.clients.browser.client-authentication-methods=none
quarkus.authorization-server.clients.browser.authorization-grant-types=authorization_code
quarkus.authorization-server.clients.browser.redirect-uris=https://app.example.com/callback
quarkus.authorization-server.clients.browser.scopes=message.read
```

These are client fragments. Configure the [issuer](./configuration#issuer), [signing keys](./signing) and application user authentication separately. See [Authorization Code + PKCE](/guide/authorization-code) for the browser flow.

[config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/AuthorizationServerRuntimeConfig.java
[producer]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/RegisteredClientRepositoryProducer.java
[client]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/client/RegisteredClient.java
[client-settings]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/settings/ClientSettings.java
[token-settings]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/settings/TokenSettings.java
[secret-verifier]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/client/BcryptClientSecretVerifier.java
[assertion-verifier]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/client/authentication/JwtClientAssertionVerifier.java
[x509-provider]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/client/authentication/X509ClientCertificateAuthenticationProvider.java
[pkce]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/exchange/PkceVerifier.java
[jwks]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/client/authentication/ClientJwkSetCache.java
[jwt-generator]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/token/JwtGenerator.java
