# Storage and signing keys

The default stores are in-memory and unconfigured signing keys are temporary. These defaults help start a local application; persistent deployments need an explicit storage and key strategy.

## Install JDBC stores through CDI

The same `quarkus-authorization-server` extension includes the in-memory stores, JDBC implementations, serialization and SQL resources, without bringing in Agroal or JTA. In-memory stores need no database components, and applications choose the dependencies for their custom stores. JDBC implementations accept a standard `javax.sql.DataSource`; wire the repository beans as shown below.

For a Quarkus-managed datasource, explicitly add `io.quarkus:quarkus-agroal` and the Quarkus JDBC driver for your database, such as `io.quarkus:quarkus-jdbc-postgresql`. Configure the datasource:

```properties
quarkus.datasource.db-kind=postgresql
quarkus.datasource.username=authorization_server
quarkus.datasource.password=${AUTHORIZATION_SERVER_DB_PASSWORD}
quarkus.datasource.jdbc.url=jdbc:postgresql://database:5432/authorization_server
```

Provide the three repository contracts:

```java
import javax.sql.DataSource;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcJsonCodec;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;

@Singleton
public class AuthorizationStorage {
    @Produces
    @Singleton
    RegisteredClientRepository clients(DataSource dataSource, JdbcJsonCodec jsonCodec) {
        return new JdbcRegisteredClientRepository(dataSource, jsonCodec);
    }

    @Produces
    @Singleton
    OAuth2AuthorizationService authorizations(DataSource dataSource, RegisteredClientRepository clients, JdbcJsonCodec jsonCodec) {
        return new JdbcOAuth2AuthorizationService(dataSource, clients, jsonCodec);
    }

    @Produces
    @Singleton
    OAuth2AuthorizationConsentService consents(DataSource dataSource, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(dataSource, clients);
    }
}
```

This replaces the default stores. Register clients through your repository or application initialization; `quarkus.authorization-server.clients.*` does not seed a custom repository.

The extension does not create or migrate tables. Use these bundled schemas as inputs for migrations appropriate to your database:

- `META-INF/quarkus-authorization-server/schema/oauth2-registered-client-schema.sql`
- `META-INF/quarkus-authorization-server/schema/oauth2-authorization-schema.sql`
- `META-INF/quarkus-authorization-server/schema/oauth2-authorization-consent-schema.sql`

When loading a script from code, use the corresponding JDBC implementation's `SCHEMA_LOCATION` constant. The scripts have a dedicated classpath namespace, independent of Java packages, and are not served over HTTP.

The examples initialize embedded H2 themselves. Their startup schema helpers are demonstration code, not a production migration service. PostgreSQL configuration above illustrates datasource wiring; it is not evidence of a PostgreSQL migration test.

Source: [`AuthorizationServerPersistence`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/src/main/java/io/quarkiverse/authorization/server/example/authorizationcode/authorizationserver/config/AuthorizationServerPersistence.java).

## JDBC JSON codec

`JdbcOAuth2AuthorizationService` and `JdbcRegisteredClientRepository` use `JdbcJsonCodec` for authorization attributes, token metadata, client settings and token settings. SQL columns and transaction boundaries are unchanged. The codec replaces the class-typed Jackson modules and their domain/collection reflection registrations.

The codec owns an isolated mapper and reads/writes JSON trees explicitly. Each document contains `kind` (the column's purpose) and `data`. There is no `formatVersion` or dependency on the library release version. For example:

```json
{
  "kind": "token-metadata",
  "data": {
    "invalidated": false,
    "claims": {
      "nbf": { "type": "instant", "value": "2030-01-01T00:00:00Z" }
    },
    "extensions": {}
  }
}
```

Known fields use stable names such as `identity`, `authorizationRequest`, `session` and `tokenFormat`; the codec translates runtime attribute keys at the boundary. Identities contain only the principal name, roles and validated actor claims. Reading reconstructs a Quarkus `SecurityIdentity`, without credentials, request attributes or permission checkers.

Extension values support strings, booleans, null, the standard numeric wrappers, `BigInteger`, `BigDecimal`, `Instant`, `Duration`, string-keyed maps, lists, sets and the supported protocol value types. Values requiring type recovery use logical `type`/`value` envelopes; numeric payloads use text to preserve precision, scale and numeric type. Maps also have an explicit envelope, so business keys named `type` and `value` cannot be interpreted as codec metadata. Collections are restored as immutable interfaces, independently of their original Java implementation. Known setting fields use plain booleans and strings; omitted settings receive domain defaults.

The extension provides a `@Singleton` / `@DefaultBean` codec and collects application `@Default JdbcJsonValueAdapter<?>` CDI beans. Pass the injected codec to both repositories as shown above. Without CDI, the original constructors use a default codec; pass `new JdbcJsonCodec(adapters)` explicitly for custom values. An application producer can replace the default codec assembly. There is no `setObjectMapper()` entry point or application-wide Jackson customization. Beans with a custom qualifier such as `@Identifier` are reserved for explicit assembly and are not collected by the default codec. Adapter IDs start with `custom:`; duplicate IDs/classes and attempts to replace built-in types are rejected. Adapter payloads must be ordinary JSON trees, never Jackson POJO nodes. Unknown types, malformed protocol fields, duplicate JSON keys and excessive nesting fail explicitly. `nbf` must be restored as an `Instant`, preserving the token's not-before check.

Before returning encoded JSON, the codec parses it with the same private mapper used for reading. Jackson limits such as number, string and field-name length therefore fail before persistence; this adds one JSON parse per encoded document and does not invoke application adapters.

The codec deliberately does not read old class-typed JSON. Recreate disposable development data when adopting this change; the extension does not migrate or delete existing rows. Fixed samples for all four column kinds are maintained in [`runtime/src/test/resources/jdbc-json`](https://github.com/flynndi/quarkus-authorization-server/tree/main/runtime/src/test/resources/jdbc-json).

## Understand transaction boundaries

JDBC repositories are synchronous. The extension invokes protocol work on a worker; custom callers must also use a blocking-capable context.

Applications explicitly add `quarkus-agroal` to use a Quarkus-managed connection pool and transaction integration. Repositories check Agroal transaction participation only when its API is present; a plain JDBC `DataSource` does not require Agroal.

An Agroal connection already enlisted in an external JTA transaction follows that transaction. Otherwise each repository write uses its own local transaction. The extension does not automatically wrap an entire grant in a transaction or promise atomic single consumption under concurrent requests. Application-owned transaction boundaries must cover the actual synchronous JDBC work, not only the creation of a reactive operation.

See [`JdbcTransactionSupport`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/jdbc/JdbcTransactionSupport.java).

## Supply stable signing keys

Without signing configuration the server generates a temporary RSA key. After a restart, tokens signed by the old key cannot be verified using the new key set. Supply durable keys for a deployed issuer:

```properties
quarkus.authorization-server.issuer=https://auth.example.com
quarkus.authorization-server.signing.key-id=auth-key-1
quarkus.authorization-server.signing.algorithm=RS256
quarkus.authorization-server.signing.private-key-location=file:/run/secrets/auth-private-key.pem
quarkus.authorization-server.signing.public-key-location=file:/run/secrets/auth-public-key.pem
```

The private PEM is PKCS#8; the public PEM is X.509 SubjectPublicKeyInfo. The loader also supports `classpath:` and ordinary file paths. Bundled example PEMs are public fixtures and must not be reused for a real issuer.

For a planned rotation, keep an old verification key alongside the new signing key:

```properties
quarkus.authorization-server.signing.active-key-id=current
quarkus.authorization-server.signing.keys.previous.public-key-location=file:/run/secrets/previous-public.pem
quarkus.authorization-server.signing.keys.current.private-key-location=file:/run/secrets/current-private.pem
quarkus.authorization-server.signing.keys.current.public-key-location=file:/run/secrets/current-public.pem
```

Use this multi-key configuration instead of the single-key block. Map keys are `kid` values; algorithms default to RS256 here. Retain verification keys while their tokens remain valid, accounting for resource-server JWKS caching. Key loading is not a hot-rotation API; deploy or restart with the intended key set. A CDI `AuthorizationServerKeySource` replaces the configuration-backed source when the application owns key loading.

Source: [`ConfiguredAuthorizationServerKeySource`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/token/ConfiguredAuthorizationServerKeySource.java). See [Signing keys](/reference/signing) for all properties and [Multiple issuers](/reference/configuration#multiple-issuers) for tenant isolation.
