# Client Credentials

应用以自身身份调用 API 时使用 Client Credentials，例如定时任务。流程不需要资源所有者登录，也没有 consent 页面；access token 代表客户端自身。

## 运行示例

[快速开始](./getting-started)说明如何将扩展引入自己的应用。可选的 [Client Credentials 示例](https://github.com/flynndi/quarkus-authorization-server/tree/main/examples/client-credentials)注册 `machine-client` 并提供 `/api/messages`。在仓库根目录启动：

```shell
./gradlew :examples:client-credentials:quarkusDev --no-parallel
```

另开终端请求 token：

```shell
curl -sS -u machine-client:machine-secret \
  -d grant_type=client_credentials \
  -d scope=message.read \
  http://127.0.0.1:8080/oauth2/token
```

这里使用公开演示凭据。示例注册 HTTP Basic 认证，存储 secret 的 bcrypt hash，并显式设置 access token 有效期为两分钟；这不是所有客户端的默认值。

流程依次认证客户端、检查注册的 grant 和 scope、签发 access token 并保存授权记录，不签发 refresh token 或 ID Token。Token 到期后，客户端再次使用自己的凭据申请。

## 在自己的应用里配置客户端

使用默认内存客户端仓储的应用，可以直接通过配置注册机器客户端：

```properties
quarkus.authorization-server.issuer=https://auth.example.com
quarkus.authorization-server.clients.machine.client-authentication-methods=client_secret_basic
quarkus.authorization-server.clients.machine.client-secret=${MACHINE_CLIENT_SECRET_BCRYPT}
quarkus.authorization-server.clients.machine.authorization-grant-types=client_credentials
quarkus.authorization-server.clients.machine.scopes=message.read
quarkus.authorization-server.clients.machine.access-token-time-to-live=PT2M
```

Map key `machine` 就是 client ID。`MACHINE_CLIENT_SECRET_BCRYPT` 提供 bcrypt hash，调用方通过 HTTPS 发送原始 secret。部署时还需配置[持久签名密钥和存储](./storage-and-keys)。

这种配置方式与示例中的 JDBC 注册是两种选择。示例已提供自己的 `RegisteredClientRepository`，因此向该示例添加 `clients.machine.*` 不会自动向 JDBC 插入新客户端。使用自定义仓储时，由应用通过该仓储注册客户端。

## 访问资源

以 `Authorization: Bearer <access_token>` 发送 token。本示例中：

- Token subject 和默认 audience 都是 `machine-client`。
- 资源服务器验证 issuer、签名、有效期及预期 audience。
- `@PermissionsAllowed("message.read")` 要求由 `quarkus-oidc` 映射的 token scope。

客户端注册限定可申请的 scope，不自动赋予所有 API 权限。角色、scope 与业务规则见[身份与权限](./identity-and-access)，资源端配置见 [Token 与资源服务器](./tokens-and-resources)。

本示例打开 OIDC 是为了给资源服务器提供发现端点；Client Credentials 协议本身不依赖 OIDC。

源码：[`ClientCredentialsServerConfig`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/client-credentials/src/main/java/io/quarkiverse/authorization/server/example/clientcredentials/ClientCredentialsServerConfig.java)、[`MessageResource`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/client-credentials/src/main/java/io/quarkiverse/authorization/server/example/clientcredentials/MessageResource.java)、[`RegisteredClientRepositoryProducer`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/RegisteredClientRepositoryProducer.java)。
