# Client Credentials

Use Client Credentials for an application acting on its own behalf, such as a scheduled job calling an API. There is no resource-owner login or consent page. The access token represents the client.

## Run the example

[Getting Started](./getting-started) explains how to add the extension to your own application. The optional [Client Credentials example](https://github.com/flynndi/quarkus-authorization-server/tree/main/examples/client-credentials) registers `machine-client` and exposes `/api/messages`. Start it from the repository root:

```shell
./gradlew :examples:client-credentials:quarkusDev --no-parallel
```

In another terminal, request a token:

```shell
curl -sS -u machine-client:machine-secret \
  -d grant_type=client_credentials \
  -d scope=message.read \
  http://127.0.0.1:8080/oauth2/token
```

These are public demo credentials. The example registers HTTP Basic authentication and stores a bcrypt hash of the secret. Its access token lifetime is explicitly two minutes; this is an example setting, not the default for every client.

The flow authenticates the client, checks its registered grant and scopes, issues an access token and saves an authorization. It does not issue a refresh token or ID Token. When the token expires, the client authenticates again to request another one.

## Configure a client in your own application

An application using the default in-memory client repository can register a machine client entirely through configuration:

```properties
quarkus.authorization-server.issuer=https://auth.example.com
quarkus.authorization-server.clients.machine.client-authentication-methods=client_secret_basic
quarkus.authorization-server.clients.machine.client-secret=${MACHINE_CLIENT_SECRET_BCRYPT}
quarkus.authorization-server.clients.machine.authorization-grant-types=client_credentials
quarkus.authorization-server.clients.machine.scopes=message.read
quarkus.authorization-server.clients.machine.access-token-time-to-live=PT2M
```

The map key `machine` is the client ID. Supply a bcrypt hash in `MACHINE_CLIENT_SECRET_BCRYPT`; the caller sends the original secret over HTTPS. Add [persistent signing keys and storage](./storage-and-keys) for a deployed application.

This configuration is an alternative to the example's JDBC registration. The example provides its own `RegisteredClientRepository`, so adding `clients.machine.*` to that example will not insert another client into JDBC. With a custom repository, register clients through that repository.

## Resource access

Send the access token as `Authorization: Bearer <access_token>`. In this example:

- The token subject and default audience are `machine-client`.
- The resource server validates the issuer, signature, expiration and expected audience.
- `@PermissionsAllowed("message.read")` requires the token scope mapped by `quarkus-oidc`.

Client registration bounds which scopes can be requested. It does not grant every API permission automatically. See [identity and access](./identity-and-access) for roles, scopes and business rules, and [tokens and resource servers](./tokens-and-resources) for the resource-side configuration.

OIDC is enabled in this example to provide discovery for its resource server. Client Credentials itself does not require OIDC.

Sources: [`ClientCredentialsServerConfig`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/client-credentials/src/main/java/io/quarkiverse/authorization/server/example/clientcredentials/ClientCredentialsServerConfig.java), [`MessageResource`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/client-credentials/src/main/java/io/quarkiverse/authorization/server/example/clientcredentials/MessageResource.java), [`RegisteredClientRepositoryProducer`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/RegisteredClientRepositoryProducer.java).
