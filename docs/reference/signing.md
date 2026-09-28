# Signing keys

Prefix: `quarkus.authorization-server.signing`. All properties on this page are **`RUN_TIME`** and apply to the default `ConfiguredAuthorizationServerKeySource`. Change values at startup without rebuilding; native classpath resources must already be [included in the image](#native-resources). Key loading does not provide a hot-rotation API.

Mapping: [SigningConfig and SigningKeyConfig][config]. Loading and validation: [ConfiguredAuthorizationServerKeySource][source] and [AuthorizationServerKeyManager][manager].

## Single key {#single-key}

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Property | Type / default | Requirement or behavior |
| --- | --- | --- |
| `algorithm` | `String` · `RS256` | Algorithm for the configured single key; supported values are listed below. Setting only this value does not select an ephemeral key algorithm. |
| `key-id` | `String` · unset | Required and nonblank when a single key is configured; becomes JWT/JWK `kid`. |
| `private-key-location` | `String` · unset | Required with the single-key configuration; PKCS#8 private PEM. |
| `public-key-location` | `String` · unset | Required with the single-key configuration; X.509 SubjectPublicKeyInfo public PEM. |

</div>

Supplying any of `key-id`, `private-key-location` or `public-key-location` selects single-key mode and requires all three. With none of them and an empty `keys` map, the source generates an ephemeral RSA-2048 key, RS256 algorithm and random `kid`, even if `algorithm` alone was changed. Normal launch mode logs a warning. Restarting loses that key; independent instances generate different keys.

```properties
quarkus.authorization-server.signing.key-id=auth-key-1
quarkus.authorization-server.signing.algorithm=RS256
quarkus.authorization-server.signing.private-key-location=file:/run/secrets/auth-private-key.pem
quarkus.authorization-server.signing.public-key-location=file:/run/secrets/auth-public-key.pem
```

## Multiple keys {#multiple-keys}

The `keys` map is empty by default. Its entry name is the `kid`; there is no separate `key-id` property inside an entry.

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Property | Type / default | Requirement or behavior |
| --- | --- | --- |
| `active-key-id` | `String` · unset | Requires `keys`. Mandatory when the map has more than one entry; must name a key with a private key. One entry is selected automatically. |
| `keys."<kid>".algorithm` | `String` · `RS256` | Algorithm of this key. The map key must not be blank. |
| `keys."<kid>".private-key-location` | `String` · unset | Optional for verification-only keys; required for the active signing key. |
| `keys."<kid>".public-key-location` | `String` · unset | Required for every entry, including keys with a private key. |

</div>

Do not combine `keys.*` with single-key `key-id`, `private-key-location` or `public-key-location`. The top-level `algorithm` is used only for configured single-key mode; each map entry uses its own algorithm.

Keep the previous public key while introducing a new signing key:

```properties
quarkus.authorization-server.signing.active-key-id=current
quarkus.authorization-server.signing.keys.previous.public-key-location=file:/run/secrets/previous-public.pem
quarkus.authorization-server.signing.keys.current.private-key-location=file:/run/secrets/current-private.pem
quarkus.authorization-server.signing.keys.current.public-key-location=file:/run/secrets/current-public.pem
```

The JWKS endpoint publishes all loaded public keys. Retain old verification keys while issued tokens remain valid and account for resource-server JWKS caches. This is a configured rotation on restart, not automatic periodic rotation.

## Native image resources {#native-resources}

With the default key source, the extension automatically includes build-visible `classpath:` private/public key resources in the native image. This covers both single-key properties and `keys."<kid>".*`, including verification-only public keys. For example, `private-key-location=classpath:keys/private.pem` does not also require a `quarkus.native.resources.includes` entry. Only resource locations are registered during augmentation; key loading and validation remain runtime operations.

The active build profile and resolvable configuration expressions determine which resources are included. A location supplied only at runtime cannot add resources to an existing executable: include the resource explicitly at build time using `quarkus.native.resources.includes`, or use an external filesystem location. Ordinary paths and `file:` locations remain external files and are not bundled automatically.

An application-provided `AuthorizationServerKeySource` or multiple-issuer tenant key source remains responsible for its resources. Unused default signing configuration is not automatically bundled when CDI replaces the default source or multiple issuers are enabled.

## Formats and algorithm selection {#algorithms}

Locations support `classpath:keys/key.pem`, `file:/run/secrets/key.pem` and ordinary filesystem paths. The default loader reads local PEM files; an HTTP URL is not a remote key-fetching option. Use `-----BEGIN PRIVATE KEY-----` for an unencrypted PKCS#8 private key and `-----BEGIN PUBLIC KEY-----` for an X.509 SubjectPublicKeyInfo public key. A certificate PEM is not interchangeable with that public-key format.

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Algorithms | Key requirement |
| --- | --- |
| `RS256`, `RS384`, `RS512` | RSA key pair |
| `PS256`, `PS384`, `PS512` | RSA key pair, RSA-PSS signatures |
| `ES256` | EC P-256 |
| `ES384` | EC P-384 |
| `ES512` | EC P-521 |

</div>

The key manager validates key type, EC curve, unique/nonblank IDs and matching public/private pairs. The active key must contain a private key. JWT access tokens normally use the active key; an ID Token uses the client's [id-token-signature-algorithm](./clients#token-settings). If that algorithm differs from the active key's algorithm, there must be exactly one signing private key for the requested algorithm. Multiple private keys for a non-active algorithm are ambiguous and rejected.

OIDC additionally requires an RS256 signing private key in the available set, even if a particular client chooses a different ID Token algorithm. A public verification-only RS256 key does not meet this requirement. Source: [OidcProviderConfigurationEndpointHandler][oidc].

## Application-owned keys {#custom-source}

A CDI `AuthorizationServerKeySource` replaces the default source completely, so `signing.*` no longer loads keys through that source. Return JCA key material in a `KeySet`; the key manager still performs its validation. This interface does not implement remote signing or promise repeated `load()` calls for live updates.

[Multiple issuers](./configuration#multiple-issuers) require a key source in each `AuthorizationServerTenant` and reject global signing configuration. Each tenant must meet the same key validation rules.

[config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/AuthorizationServerRuntimeConfig.java
[source]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/token/ConfiguredAuthorizationServerKeySource.java
[manager]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/token/AuthorizationServerKeyManager.java
[oidc]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/oidc/web/OidcProviderConfigurationEndpointHandler.java
