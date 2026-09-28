# Reference

Look up configuration, HTTP contracts and CDI integration rules. Each section links to the implementation that defines its behavior.

## Configuration

| Page | What you can look up |
| --- | --- |
| [Server configuration](./configuration) | Build/runtime phases, switches, endpoint paths, issuer and tenant requirements |
| [Registered clients](./clients) | Authentication, grants, redirects, scope, `ClientSettings` and `TokenSettings` |
| [Signing keys](./signing) | PEM locations, single/multiple keys, active key selection and CDI replacement |
| [DPoP](./dpop) | Proof algorithms, time limits and default replay-store capacity |

Properties use the `quarkus.authorization-server` prefix. A section's phase and source apply to every row in its tables. Runtime values are supplied at startup; they are not a promise of live updates. The client tables distinguish config-mapping defaults from defaults inferred by `RegisteredClient`, `ClientSettings` and `TokenSettings`.

## Integration and protocol behavior

| Page | What you can look up |
| --- | --- |
| [OAuth endpoints](./endpoints) | Authentication, authorize/consent, six token grants, introspection, revocation, device and PAR requests |
| [OIDC and registration](./oidc-and-registration) | UserInfo, logout, protected/open registration, accepted metadata and errors |
| [CDI extension points](./extensions) | Default implementations, replacement/composition rules, user identity, tenants and custom grants |
| [Protocol support](./protocol-support) | Current DPoP, refresh, PAR, registration, persistence and issuer boundaries |

Endpoint and SPI source links are pinned to the audited commit. Application wiring and JDBC configuration are covered by the guides below.

For application guidance, start with [Architecture](/guide/architecture), [Identity and access](/guide/identity-and-access) or [Storage and signing keys](/guide/storage-and-keys). First time using the extension? Follow [Getting started](/guide/getting-started).
