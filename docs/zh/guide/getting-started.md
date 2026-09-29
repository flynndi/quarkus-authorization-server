# 快速开始

将授权服务器与资源 API 运行在**两个独立的 Quarkus 应用**中。在授权服务器登录，由 OAuth 客户端通过 **Authorization Code** 获取 access token，再携带 token 调用由 **`quarkus-oidc`** 保护的 API。

授权服务器管理用户，通过 Quarkus Form 完成登录。资源 API 信任该服务器签发的 token，不查询用户密码，也不使用授权服务器的登录会话。这适用于新建系统，也适用于已有自己的用户服务的系统。

| 角色 | 本篇中的实现 | 职责 |
| --- | --- | --- |
| 授权服务器 | `authorization-server`，端口 `8080` | 用户登录、consent、客户端认证和 token 签发 |
| 资源服务器 | `resource-server`，端口 `8081` | 验证 access token，要求 `/api/messages` 的调用者具有 `message.read` 权限 |
| OAuth 客户端 | 浏览器与终端命令 | 发起授权、接收授权码、兑换 token、调用 API |

浏览器在授权服务器和回调页之间跳转；终端将授权码提交到授权服务器的 token 端点，再携带 access token 请求资源 API。为避免构建前端或再启动第三个服务器，本篇由资源应用托管一个静态回调辅助页，它不负责兑换 token。

准备 **JDK 21**、**Maven 3.9+**、**curl 7.76+**、**Python 3** 和浏览器。确保 `8080`、`8081` 端口空闲，全程使用 `localhost`。不需要下载本仓库源码或准备数据库。

## 1. 创建授权服务器

创建工作目录与第一个应用：

```shell
mkdir oauth-quickstart
cd oauth-quickstart
mvn io.quarkus.platform:quarkus-maven-plugin:@QUARKUS_VERSION@:create \
  -DplatformVersion=@QUARKUS_VERSION@ \
  -DprojectGroupId=org.acme \
  -DprojectArtifactId=authorization-server \
  -Dextensions=config-yaml,elytron-security-common \
  -DnoCode
cd authorization-server
```

在该应用 `pom.xml` 顶层的 `<dependencies>` 中增加授权服务器依赖：

```xml
<dependency>
    <groupId>@EXTENSION_GROUP@</groupId>
    <artifactId>quarkus-authorization-server</artifactId>
    <version>@EXTENSION_VERSION@</version>
</dependency>
```

如果已有应用，使用 Quarkus `@QUARKUS_VERSION@` 的 platform BOM，并引入以下依赖：

| 依赖 | 职责 |
| --- | --- |
| `@EXTENSION_GROUP@:quarkus-authorization-server:@EXTENSION_VERSION@` | 授权端点、客户端注册、token 签发与默认浏览器页面 |
| `io.quarkus:quarkus-config-yaml` | 读取 `application.yml` |
| `io.quarkus:quarkus-elytron-security-common` | 使用 `BcryptUtil` 验证演示用户的密码 |

`io.quarkus` 依赖的版本由 platform 管理。应用只需引入授权服务器的 runtime 产物，Quarkus 会自动解析对应的 deployment 产物。提供授权端点不需要引入 `quarkus-oidc` 或 Quarkus REST。

## 2. 通过 CDI Bean 提供用户认证

在 **`authorization-server`** 中创建 `src/main/java/org/acme/DemoIdentityProviders.java`：

<<< @/snippets/getting-started/DemoIdentityProviders.java

这里定义了用户 **`alice` / `alice-password`**，包含用户名、密码哈希、角色和权限。接入实际应用时，将 Map 替换为自己的用户服务。

两个 Provider 复用同一套用户查询：

- `UsernamePasswordAuthenticationRequest`：校验提交给 Quarkus Form 的用户名和密码。
- `TrustedAuthenticationRequest`：后续请求中，在 Quarkus Form 验证加密登录 Cookie 后，重新加载用户身份。

这两个 Bean 只属于授权服务器。资源服务器通过 `quarkus-oidc` 从 access token 建立身份。

## 3. 配置客户端与登录

在 **`authorization-server`** 中创建 `src/main/resources/application.yml`。如果生成的应用中有空的 `application.properties`，将它删除。

<<< @/snippets/getting-started/authorization-server.yml

**`quarkus.authorization-server`** 提供 OAuth 端点，将 `quickstart-client` 注册到默认内存仓储，并启用内置登录页。**`quarkus.http.auth.form.enabled`** 启用 Quarkus Form 认证。启用 OIDC 后发布 discovery metadata，独立的资源服务器据此发现 issuer 和 JWKS。

这是一个 confidential client：在 token 端点使用 HTTP Basic 认证，client ID 为 **`quickstart-client`**，client secret 为 **`quickstart-secret`**。YAML 已提供该演示 secret 的 bcrypt 哈希，直接复制即可。`require-proof-key: false` 表示本篇不要求 PKCE，仍需用户同意授予 `message.read`。

配置 Map 的键 `quickstart-client` 就是 client ID；注册在 **`8081`** 端口的回调地址必须与授权请求、token 请求中的地址完全一致。终端模拟后端 OAuth 客户端，只在兑换 token 时使用 client secret。不要将它放进回调页面或前端 JavaScript。

本地演示使用默认的客户端、授权记录、consent 内存仓储和临时 RSA 签名密钥，不需要额外提供仓储 Bean 或 PEM 文件。重启授权服务器会丢失授权记录和 consent，并生成新的签名密钥。

## 4. 创建资源服务器

回到父目录 **`oauth-quickstart`**，在授权服务器旁边创建第二个应用：

```shell
cd ..
mvn io.quarkus.platform:quarkus-maven-plugin:@QUARKUS_VERSION@:create \
  -DplatformVersion=@QUARKUS_VERSION@ \
  -DprojectGroupId=org.acme \
  -DprojectArtifactId=resource-server \
  -Dextensions=rest-jackson,config-yaml,oidc \
  -DnoCode
cd resource-server
```

该应用通过 `quarkus-rest-jackson` 提供 JSON API，使用 `quarkus-config-yaml` 读取配置，通过 `quarkus-oidc` 验证 Bearer token。不需要引入授权服务器依赖、用户认证 Bean 或签名私钥。

## 5. 配置资源 API 与回调页

在 **`resource-server`** 中创建 `src/main/resources/application.yml`。如果存在空的 `application.properties`，将它删除。

<<< @/snippets/getting-started/resource-server.yml

API 监听 **`8081`**，`quarkus.oidc.auth-server-url` 指向 **`8080`** 上的授权服务器。`quarkus-oidc` 发现其公钥，校验 token 的签名、issuer、有效期和 audience。audience 必须包含 `quickstart-client`，这是授权服务器为该客户端签发 token 时的默认 audience。

`/api/*` 的规则选择 **Bearer** 认证，只有 Form 登录 Cookie 不能访问 API。该资源服务器在本地验证 JWT，不向授权服务器提交用户密码，也不需要每次调用 API 都去 token 端点认证。

在 **`resource-server`** 中创建 `src/main/java/org/acme/MessageResource.java`：

<<< @/snippets/getting-started/MessageResource.java

`quarkus-oidc` 将验证后的 token scope 映射为权限。`@PermissionsAllowed("message.read")` 检查调用该接口所需的权限。

仍在 **`resource-server`** 中，创建 `src/main/resources/META-INF/resources/callback.html`：

<<< @/snippets/getting-started/callback.html

这个可公开访问的静态页面只是教程客户端的回调落点，由终端校验 `state` 并兑换授权码。接入自己的应用时，应注册实际 OAuth 客户端的回调地址；托管回调页不是资源服务器的必要职责。

## 6. 启动两个应用

打开两个终端，初始目录都为 **`oauth-quickstart`**。第一个终端启动授权服务器：

```shell
cd authorization-server
mvn quarkus:dev
```

等待 `http://localhost:8080` 启动。第二个终端先检查 discovery，再启动资源服务器：

```shell
curl --fail-with-body -sS http://localhost:8080/.well-known/openid-configuration
cd resource-server
mvn quarkus:dev -Ddebug=5006
```

等待 `http://localhost:8081` 启动。第二个 debug 端口避免与授权服务器的开发模式调试器冲突。先启动授权服务器，让资源服务器可以在启动时访问 discovery。本篇使用临时签名密钥，如果重启授权服务器导致密钥变化，请同时重启资源服务器并重新获取 token。

## 7. 登录并获取 access token {#login-and-token}

打开**第三个终端**，生成随机 `state` 和授权地址。`state` 用来确认回调对应自己发起的请求。后续命令都在这个终端中执行，不要关闭它：

<<< @/snippets/getting-started/authorize.sh{shell}

在浏览器打开输出的 URL：

1. 在 **`localhost:8080`** 上使用 **`alice`** / **`alice-password`** 登录。
2. 在 consent 页面勾选 **`message.read`**，再点击 **Approve**。
3. 浏览器回到 `http://localhost:8081/callback.html?code=…&state=…`。
4. 从地址栏复制**完整回调 URL**。

登录负责认证用户；回调中返回的是**授权码**，还不是 access token。接下来使用 client ID 和 client secret，向 **`8080`** 上的授权服务器兑换授权码。

回到同一个终端，先执行下面这一行。在 `read` 等待输入时粘贴回调 URL，然后按回车：

```shell
read -r QAS_CALLBACK
```

再校验 `state`，使用 HTTP Basic 认证客户端并兑换 token：

<<< @/snippets/getting-started/exchange.sh{shell}

成功后，`QAS_ACCESS_TOKEN` 就是 access token。`curl -u` 将客户端凭据放在 HTTP Basic 请求头中。这组凭据用于认证 OAuth 客户端，登录页的 `alice` / `alice-password` 用于认证用户。token 响应包含 `token_type: Bearer` 和 `expires_in`；该客户端不请求 refresh token 或 ID Token。

授权码有效期短且只能使用一次。如果过期、重复使用或 state 校验失败，重新执行本节发起新的授权请求。如果拒绝 consent，回调会包含 OAuth 错误，上面的命令会停止，不再请求 token。

## 8. 携带 token 请求资源接口

在同一个终端，携带 access token 请求 **`8081`** 上的资源 API：

```shell
curl --fail-with-body -sS -H "Authorization: Bearer $QAS_ACCESS_TOKEN" \
  http://localhost:8081/api/messages
```

预期返回以下 JSON，字段顺序不影响结果：

```json
{"subject":"alice","message":"Hello, OAuth!"}
```

资源 API 在不带 token 时返回 `401`，可以单独验证：

```shell
curl -i http://localhost:8081/api/messages
```

token 认证成功但缺少所需的 `message.read` 权限时返回 `403`。资源 API 独立判断访问权限，不依赖授权服务器的登录会话。

用户的角色和权限不会自动写入 token，也不会自动与客户端 scope 取交集。本例通过授予的 scope 控制 API 访问；业务需要限制用户可授权范围时，请提供相应的用户访问策略，参见[身份与权限](./identity-and-access)。

## 接入自己的应用

- [配置参考](/zh/reference/)：客户端设置、默认页面、端点路径与 CDI 替换点。
- [存储与密钥](./storage-and-keys)：持久化仓储、签名密钥，以及独立的 Quarkus Form 会话加密密钥。
- [Token 与资源服务器](./tokens-and-resources)：issuer/audience 校验、token 表示与 claims 定制。
- [Authorization Code + PKCE](./authorization-code)：进阶阅读，使用 PKCE 的 public Vue 客户端、OIDC 与登出。[仓库示例](https://github.com/flynndi/quarkus-authorization-server/tree/main/examples)可作为可选的完整运行参考。
- [Client Credentials](./client-credentials)：无需用户登录的机器间调用。

部署时使用 HTTPS 和公开的 issuer、客户端回调地址，替换演示凭据，配置持久化密钥和存储。授权服务器与资源 API 可以运行在不同主机上；资源服务器的 `quarkus.oidc.auth-server-url` 指向授权服务器的公开 issuer。
