# Storage and signing keys

The default stores are in-memory and unconfigured signing keys are temporary. These defaults help start a local application; persistent deployments need an explicit storage and key strategy.

## Install JDBC stores through CDI

Add the Quarkus JDBC driver for your database, such as `io.quarkus:quarkus-jdbc-postgresql`. Configure its datasource:

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
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;

@Singleton
public class AuthorizationStorage {
    @Produces
    @Singleton
    RegisteredClientRepository clients(DataSource dataSource) {
        return new JdbcRegisteredClientRepository(dataSource);
    }

    @Produces
    @Singleton
    OAuth2AuthorizationService authorizations(DataSource dataSource, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(dataSource, clients);
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

## Understand transaction boundaries

JDBC repositories are synchronous. The extension invokes protocol work on a worker; custom callers must also use a blocking-capable context.

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
