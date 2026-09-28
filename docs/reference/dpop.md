# DPoP configuration

Prefix: `quarkus.authorization-server.dpop`. All properties are **`RUN_TIME`**: supply them at startup without rebuilding; there is no per-request config refresh. DPoP is supported by default and used when the client supplies a valid proof on a supported flow. There is no `enabled` switch.

Mapping: [DPoPConfig][config]. Validation: [DPoPProofVerifier][verifier] and [InMemoryDPoPReplayStore][store].

## Properties {#properties}

<div class="reference-table" role="region" aria-label="Configuration table; scroll horizontally if needed" tabindex="0">

| Property | Type / default | Constraint or use |
| --- | --- | --- |
| `proof-algorithms` | `Set<SignatureAlgorithm>` · `ES256,RS256` | Nonempty. RS256/384/512, PS256/384/512 and ES256/384/512 are supported values. The same set is published in OAuth/OIDC algorithm discovery. |
| `proof-max-age` | `Duration` · `1M` | Must be positive. The proof expires at `iat + proof-max-age`; clock skew does not extend this deadline. |
| `clock-skew` | `Duration` · `5S` | Must be nonnegative. Allows `iat` up to this far in the future. |
| `max-proof-length` | int · `16384` | Must be positive. Maximum compact proof string length, checked before JWT parsing. |
| `replay-cache-size` | int · `100000` | Must be positive. Maximum entries in the default in-memory replay store. Does not configure a custom store. |

</div>

These are the defaults, shown as a configuration fragment:

```properties
quarkus.authorization-server.dpop.proof-algorithms=ES256,RS256
quarkus.authorization-server.dpop.proof-max-age=1M
quarkus.authorization-server.dpop.clock-skew=5S
quarkus.authorization-server.dpop.max-proof-length=16384
quarkus.authorization-server.dpop.replay-cache-size=100000
```

Proof algorithms are independent of the authorization server's [token signing keys](./signing). For example, an ES256 proof can bind an access token signed with RS256. This allowlist controls accepted proofs, not the token signature algorithm.

## Replay store and scope {#replay-store}

The default replay store is bounded and local to one JVM. It removes expired entries during use and rejects a claim when full; it does not evict unexpired entries to admit new proofs. A CDI `DPoPReplayStore` replaces it when the application needs another storage strategy. Increasing the capacity does not provide cross-instance replay protection.

Authorization Code, Refresh Token, Client Credentials, Device Code and Token Exchange accept DPoP proofs. Password requests with a DPoP header are rejected. Token Exchange binds the **output** token; it does not add input-token binding validation or inheritance. UserInfo accepts DPoP-bound tokens with their resource-access proof. These settings do not configure a separate resource server's DPoP validation.

There are no settings for server nonces, a built-in shared replay backend or mandatory DPoP. The public-client refresh restriction is separate: public Authorization Code clients may obtain Bearer access tokens without DPoP, but require the supported DPoP-bound flow to obtain and use refresh tokens. See [Tokens and resource servers](/guide/tokens-and-resources).

[config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/AuthorizationServerRuntimeConfig.java
[verifier]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/dpop/DPoPProofVerifier.java
[store]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/dpop/InMemoryDPoPReplayStore.java
