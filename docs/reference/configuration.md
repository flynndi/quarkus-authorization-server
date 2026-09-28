# Server configuration

All extension properties start with `quarkus.authorization-server`. The tables below omit that prefix. Use `application.properties`, or `application.yaml` with `quarkus-config-yaml`. External values use Quarkus Config; application behavior and repositories use CDI.

For client and cryptographic settings, see [Registered clients](./clients), [Signing keys](./signing) and [DPoP](./dpop).

## Configuration phases {#phases}

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Phase | Change takes effect | Source |
| --- | --- | --- |
| `BUILD_TIME` | Rebuild the application. These values control installed routes and beans. | [AuthorizationServerBuildTimeConfig][build-config] |
| `BUILD_AND_RUN_TIME_FIXED` | Rebuild the application. Runtime code can read these values, but deployment fixes them. | [AuthorizationServerOidcConfig][oidc-config], [AuthorizationServerClientRegistrationConfig][registration-config] |
| `RUN_TIME` | Supply values when starting the application; no rebuild is required. This is not a hot-reload contract. | [AuthorizationServerRuntimeConfig][runtime-config] |

</div>

The phase stated for each section applies to every row in it. Defaults marked **unset** mean the mapping has no value; conditional requirements are described separately. Quarkus HTTP, TLS, Form and datasource properties belong to their respective extensions.

## Build-time switches {#switches}

Phase: `BUILD_TIME`. Source: [AuthorizationServerBuildTimeConfig][build-config].

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Property | Type / default | Behavior |
| --- | --- | --- |
| `enabled` | boolean · `true` | Installs authorization-server endpoints and security components. Set to `false` to disable the extension's build steps. |
| `multiple-issuers-allowed` | boolean · `false` | Enables path-based issuer selection; requires runtime `issuers` and tenant CDI beans. See [Multiple issuers](#multiple-issuers). |
| `default-login-page-enabled` | boolean · `false` | Installs login/error pages and Form selection for browser endpoints, with overridable host Form defaults. Requires `quarkus.http.auth.form.enabled=true`; user identities remain application-owned. See [Browser login](#browser-login). |
| `pushed-authorization-requests-enabled` | boolean · `false` | Installs the PAR endpoint and advertises it in metadata. It does not require every client to use PAR. |

</div>

There is no separate enable switch for each grant. A client's `authorization-grant-types` determines which installed grants it may use.

## Browser login {#browser-login}

With the extension enabled, opt in using two build-time switches:

```properties
quarkus.authorization-server.default-login-page-enabled=true
quarkus.http.auth.form.enabled=true
```

The extension does not enable Quarkus Form implicitly. Enabling its pages without enabling Form fails the build. The switches install the login integration; clients, user IdentityProviders, issuer and resource-server configuration remain application responsibilities. They do not require fixed signing PEMs; see [temporary and configured keys](./signing#single-key).

When the extension, built-in pages and Quarkus Form are enabled, the extension selects Form for login/error pages, the Form POST location, authorization, device verification and (when OIDC is enabled) logout. Existing endpoint authorization policies still apply: initial authorization requests are validated before login; consent submissions and device verification require a user; logout may enter protocol validation anonymously. UserInfo, client authentication and resource APIs keep their own mechanisms.

The page and POST paths use Quarkus Form's server-absolute path conventions. Protocol paths follow HTTP root, configured endpoint paths and issuer prefixes. The default page handler only renders GET requests; selecting Form does not install additional page methods.

| Form property (`quarkus.http.auth.form.*`) | Built-in mode default |
| --- | --- |
| `login-page`, `error-page`, `post-location` | Quarkus defaults: `/login.html`, `/error.html`, `/j_security_check` |
| `landing-page` | `${quarkus.http.auth.form.login-page}`; only used when no saved request exists |
| `http-only-cookie` | `true` |
| `cookie-same-site` | `lax` |

Explicit configuration overrides these defaults through Quarkus Config. Cookie settings affect every login sharing the host's Form mechanism. Cookie names, lifetime, path, domain and session encryption keys remain Quarkus/application settings. Disabling the built-in pages removes this extra assembly and its defaults; supplying custom pages requires the application to configure mechanism selection itself.

The three extension defaults are runtime values supplied by `RunTimeConfigurationDefaultBuildItem`. Keeping the built-in page at a different URL only requires changing the Quarkus Form page properties. Replacing the login implementation requires disabling the built-in mode and explicitly configuring any cookie or landing-page settings your application needs. See [customizing browser login](/guide/authorization-code#customize-browser-login).

HTTP permissions are combined using Quarkus rules, not ordinary property override rules. Exact browser paths can be exceptions to broader `/*` policies; shared checks and matching method-specific checks still apply. Conflicting mechanisms in HTTP permission configuration at these exact paths, or in matching shared rules, fail startup with the permission name. Duplicate `form` selections are accepted. This check covers configuration entries, not arbitrary programmatic `HttpSecurity` observers or custom policies; those integrations retain Quarkus ordering and matching semantics.

Assembly: [AuthorizationServerProcessor][processor]. Mechanism selection and conflict checks: [BrowserLoginSecurityConfiguration](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/web/BrowserLoginSecurityConfiguration.java). Shared page-path parsing: [DefaultLoginPage](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/web/DefaultLoginPage.java).

## Optional protocols {#optional-protocols}

Phase: `BUILD_AND_RUN_TIME_FIXED`. Sources: [AuthorizationServerOidcConfig][oidc-config] and [AuthorizationServerClientRegistrationConfig][registration-config]. All four properties are booleans and default to `false`.

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Property | Behavior when enabled |
| --- | --- |
| `oidc.enabled` | Enables OpenID Connect Authorization Code requests, discovery, UserInfo and Logout. Clients still need appropriate scopes and redirects. The signing key set must include an RS256 private key. |
| `oidc.client-registration.enabled` | Installs protected OIDC client registration and configuration reads. Requires `oidc.enabled=true`. |
| `client-registration.enabled` | Installs independent OAuth 2.0 client registration. It does not require OIDC. Registration normally requires an initial access token with `client.create`. |
| `client-registration.open-registration-allowed` | Allows registration without a token at the OAuth registration endpoint. Has an effect only when `client-registration.enabled=true`; it does not open OIDC registration. |

</div>

Enabling registration does not define permitted client scopes. The application's registration validator owns that policy; the defaults reject nonempty requested scopes. OIDC registration stays protected even if OAuth open registration is enabled.

## Endpoint paths {#endpoint-paths}

Phase: `BUILD_TIME`. Every property below is a `String` with the shown default. Source: [AuthorizationServerBuildTimeConfig][build-config]; validation: [EndpointPathConverter][path-converter]; route installation: [AuthorizationServerProcessor][processor].

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Property | Default | Installed when |
| --- | --- | --- |
| `authorization-endpoint` | `/oauth2/authorize` | Extension enabled |
| `token-endpoint` | `/oauth2/token` | Extension enabled |
| `jwk-set-endpoint` | `/oauth2/jwks` | Extension enabled |
| `token-introspection-endpoint` | `/oauth2/introspect` | Extension enabled |
| `token-revocation-endpoint` | `/oauth2/revoke` | Extension enabled |
| `device-authorization-endpoint` | `/oauth2/device_authorization` | Extension enabled |
| `device-verification-endpoint` | `/oauth2/device_verification` | Extension enabled |
| `pushed-authorization-request-endpoint` | `/oauth2/par` | PAR enabled |
| `client-registration-endpoint` | `/oauth2/register` | OAuth registration enabled |
| `oidc-client-registration-endpoint` | `/connect/register` | OIDC and OIDC registration enabled |
| `oidc-user-info-endpoint` | `/userinfo` | OIDC enabled |
| `oidc-logout-endpoint` | `/connect/logout` | OIDC enabled |

</div>

Paths must start with `/` and cannot be blank, `/` alone, start with `//`, or contain `?` or `#`. They are paths within `quarkus.http.root-path`, not full URLs. For example, root `/server` and token endpoint `/oauth2/token` expose `/server/oauth2/token`. Changing a path does not enable an optional feature. Choose distinct paths for installed endpoints; in particular, OAuth and OIDC registration cannot share a path when both are enabled.

Discovery paths are fixed: OAuth metadata uses `/.well-known/oauth-authorization-server` before the issuer's path; OIDC discovery appends `/.well-known/openid-configuration` to the issuer. Form login and submission paths are Quarkus HTTP settings, not properties in this table; configure their server-absolute paths explicitly when using an HTTP root.

During augmentation, enabled extension protocol endpoints and fixed discovery routes are checked for overlapping effective paths and HTTP methods. Errors identify both endpoints, configuration properties, paths and conflicting methods. Resolution uses Quarkus HTTP root handling and includes issuer prefixes; disabled optional endpoints do not reserve paths. GET-only JWKS and POST-only token endpoints can share a path. PAR claims all methods to return its own 405 response, so it cannot share a path with a GET endpoint. This diagnostic covers extension protocol routes, not application routes or runtime Form page locations. Implementation: [EndpointValidationProcessor][endpoint-validation].

## Issuer {#issuer}

Phase: `RUN_TIME`. Mapping: [AuthorizationServerRuntimeConfig][runtime-config]. Validation: [AuthorizationServerRecorder][recorder] and [AuthorizationServerEndpoints][endpoints].

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Property | Type / default | Requirement |
| --- | --- | --- |
| `issuer` | `String` · unset | Required in normal launch mode for a single issuer. Must be an absolute HTTP(S) URL with a host and without query or fragment. Must be absent in multi-issuer mode. |
| `issuers."<tenant-id>"` | `Map<String, String>` entry · empty map | Required and nonempty in multi-issuer mode; forbidden otherwise. Each value is the canonical public issuer URL. |

</div>

Set the externally reachable issuer, including the public path prefix. The extension does not infer a canonical issuer from `Host` or forwarded headers. Dev/test mode permits an omitted single issuer, but leaves it unset; it is not an automatic `http://localhost:8080` default. Configure it for discovery and JWT client assertions as well as consistent token claims.

```properties
quarkus.authorization-server.issuer=https://auth.example.com
```

### Multiple issuers {#multiple-issuers}

```properties
quarkus.http.root-path=/server
quarkus.authorization-server.multiple-issuers-allowed=true
quarkus.authorization-server.issuers.alpha=https://auth.example.com/server/alpha
quarkus.authorization-server.issuers.beta=https://auth.example.com/server/beta
```

Tenant IDs match `[A-Za-z0-9_-]+`. Each URL uses `http` or `https`, has a host, has no user info/query/fragment, and its path must exactly equal the HTTP root plus the tenant ID, with no trailing slash. In this example, alpha's token endpoint is `/server/alpha/oauth2/token`; its OAuth metadata is `/.well-known/oauth-authorization-server/server/alpha`.

Each configured ID requires one resolvable `AuthorizationServerTenant` CDI bean with `@Identifier("<tenant-id>")`. It supplies client, authorization and consent stores plus a signing key source. Store instances must be distinct across tenants; the application also owns data isolation. Unknown tenant paths do not fall back to another issuer.

Single `issuer`, global `clients.*` and configured global signing keys are incompatible with this mode. Endpoint suffixes, protocol switches and DPoP parameters are shared. Changing the build-time switch requires a rebuild; updating the runtime issuer map and tenant data requires restarting with matching CDI components, not a per-request configuration update.

`AuthorizationServerContext` resolves the issuer for the current request. Startup and background work should use the concrete tenant components directly.

Source: [AuthorizationServerTenantRegistry][tenant-registry]. For a complete application, see the [multi-issuer integration example][integration-tests].

[build-config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/deployment/src/main/java/io/quarkiverse/authorization/server/deployment/AuthorizationServerBuildTimeConfig.java
[oidc-config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/AuthorizationServerOidcConfig.java
[registration-config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/AuthorizationServerClientRegistrationConfig.java
[runtime-config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/AuthorizationServerRuntimeConfig.java
[path-converter]: https://github.com/flynndi/quarkus-authorization-server/blob/main/deployment/src/main/java/io/quarkiverse/authorization/server/deployment/EndpointPathConverter.java
[processor]: https://github.com/flynndi/quarkus-authorization-server/blob/main/deployment/src/main/java/io/quarkiverse/authorization/server/deployment/AuthorizationServerProcessor.java
[recorder]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/AuthorizationServerRecorder.java
[endpoints]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/tenant/AuthorizationServerEndpoints.java
[tenant-registry]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/tenant/AuthorizationServerTenantRegistry.java
[integration-tests]: https://github.com/flynndi/quarkus-authorization-server/tree/main/integration-tests/authorization-code/src/main/java/io/quarkiverse/authorization/server/it/multipleissuers

[endpoint-validation]: https://github.com/flynndi/quarkus-authorization-server/blob/main/deployment/src/main/java/io/quarkiverse/authorization/server/deployment/EndpointValidationProcessor.java
