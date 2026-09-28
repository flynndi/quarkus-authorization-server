# 快速开始

在你自己的应用中引入 Quarkus Authorization Server，通过默认页面登录，使用 **Authorization Code** 获取 access token，再调用由 **`quarkus-oidc`** 保护的资源接口。

本篇使用一个 Quarkus 应用同时承担授权服务器和资源服务器职责，浏览器与几条终端命令充当 OAuth 客户端。不需要下载本仓库源码、构建前端或准备数据库。

准备 **JDK 21**、**Maven 3.9+**、**curl 7.76+**、**Python 3** 和浏览器。确保 `8080` 端口空闲，全程使用 `localhost`，包括回调地址。

## 1. 引入依赖

创建一个 Quarkus 应用：

```shell
mvn io.quarkus.platform:quarkus-maven-plugin:@QUARKUS_VERSION@:create \
  -DplatformVersion=@QUARKUS_VERSION@ \
  -DprojectGroupId=org.acme \
  -DprojectArtifactId=authorization-quickstart \
  -Dextensions=rest-jackson,config-yaml,oidc,elytron-security-common \
  -DnoCode
cd authorization-quickstart
```

在 `pom.xml` 中增加授权服务器依赖：

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
| `io.quarkus:quarkus-oidc` | 在资源接口验证 access token |
| `io.quarkus:quarkus-rest-jackson` | 实现应用自己的 JSON 资源接口 |
| `io.quarkus:quarkus-elytron-security-common` | 使用 `BcryptUtil` 哈希和验证演示用户的密码 |

`io.quarkus` 依赖的版本由 Quarkus platform 管理。应用只需引入授权服务器的 runtime 产物，Quarkus 会自动解析对应的 deployment 产物。

## 2. 通过 CDI Bean 提供用户认证

用户模型由应用自己管理。创建 `src/main/java/org/acme/DemoIdentityProviders.java`：

<<< @/snippets/getting-started/DemoIdentityProviders.java

这里定义了用户 **`alice` / `alice-password`**，包含用户名、密码哈希、角色和权限。接入实际应用时，将 Map 替换为自己的用户服务。

两个 Provider 复用同一套用户查询：

- `UsernamePasswordAuthenticationRequest`：校验提交给 Quarkus Form 的用户名和密码。
- `TrustedAuthenticationRequest`：后续请求中，在 Quarkus Form 验证加密登录 Cookie 后，重新加载用户身份。

它们负责授权服务器上的用户登录。资源服务器通过 `quarkus-oidc` 从 access token 建立身份，不调用这两个密码认证 Provider。

## 3. 配置客户端、登录与资源服务器

创建 `src/main/resources/application.yml`。如果生成的应用中有空的 `application.properties`，可以删除，将本教程的配置集中在一个文件中。

<<< @/snippets/getting-started/application.yml

两组配置分别承担以下职责：

- **`quarkus.authorization-server`** 提供 OAuth 端点，将 `quickstart-client` 注册到默认内存仓储，并启用内置登录页。`quarkus.http.auth.form.enabled` 启用 Quarkus Form 认证。
- **`quarkus.oidc`** 为资源接口验证 Bearer token。授权服务器启用 OIDC discovery 后，资源服务器可以发现其 JWKS 地址。较短的连接超时让这个单进程示例在自身 HTTP 监听尚未就绪时也能完成启动，并在需要时重新连接。

这是一个 confidential client：在 token 端点使用 HTTP Basic 认证，client ID 为 **`quickstart-client`**，client secret 为 **`quickstart-secret`**。YAML 已提供该演示 secret 的 bcrypt 哈希，直接复制即可。`require-proof-key: false` 表示本篇不要求 PKCE，仍需用户同意授予 `message.read`。

配置 Map 的键 `quickstart-client` 就是 client ID；注册的回调地址必须与授权请求、token 请求中的地址完全一致。这里由终端命令模拟后端 OAuth 客户端，只有兑换 token 时使用 client secret，不要将它放进回调页面或前端 JavaScript。

`/api/*` 的权限规则明确选择 **Bearer** 认证，只有浏览器登录 Cookie 不能访问资源接口。资源服务器还会检查 token 的 audience 包含 `quickstart-client`，这是授权服务器为该客户端签发 token 时的默认 audience。

本地演示使用默认的客户端、授权记录、consent 内存仓储和临时 RSA 签名密钥，不需要额外提供仓储 Bean 或 PEM 文件。重启应用会丢失授权记录和 consent，并生成新的签名密钥。

## 4. 添加受保护接口与回调页

创建 `src/main/java/org/acme/MessageResource.java`：

<<< @/snippets/getting-started/MessageResource.java

`quarkus-oidc` 验证 token，并将其中的 scope 映射为权限。`@PermissionsAllowed("message.read")` 检查调用该接口所需的权限。

创建 `src/main/resources/META-INF/resources/callback.html`：

<<< @/snippets/getting-started/callback.html

这个页面只作为教程中的回调落点，由终端校验 `state` 并兑换授权码。在有后端的应用中，回调处理和兑换由后端 OAuth 客户端完成。

## 5. 启动应用

```shell
mvn quarkus:dev
```

等待应用监听 `http://localhost:8080`。两个服务器在同一进程中，启动时可能先出现 `OIDC server is not available` 警告：HTTP 监听就绪后的首个请求会重新连接 discovery。可以先查看 discovery 文档：

```shell
curl -sS http://localhost:8080/.well-known/openid-configuration
```

## 6. 登录并获取 access token {#login-and-token}

打开**第二个终端**，生成随机 `state` 和授权地址。`state` 用来确认回调对应自己发起的请求。后续命令都在这个终端中执行，不要关闭它：

<<< @/snippets/getting-started/authorize.sh{shell}

在浏览器打开输出的 URL：

1. 使用 **`alice`** / **`alice-password`** 登录。
2. 在 consent 页面勾选 **`message.read`**，再点击 **Approve**。
3. 浏览器回到 `http://localhost:8080/callback.html?code=…&state=…`。
4. 从地址栏复制**完整回调 URL**。

登录负责认证用户；回调中返回的是**授权码**，还不是 access token。接下来使用 client ID 和 client secret 兑换授权码。

回到同一个终端，先执行下面这一行。在 `read` 等待输入时粘贴回调 URL，然后按回车：

```shell
read -r QAS_CALLBACK
```

再校验 `state`，使用 HTTP Basic 认证客户端并兑换 token：

<<< @/snippets/getting-started/exchange.sh{shell}

成功后，`QAS_ACCESS_TOKEN` 就是 access token。`curl -u` 将客户端凭据放在 HTTP Basic 请求头中。这组凭据用于认证 OAuth 客户端，登录页的 `alice` / `alice-password` 用于认证用户。token 响应包含 `token_type: Bearer` 和 `expires_in`；该客户端不请求 refresh token 或 ID Token。

授权码有效期短且只能使用一次。如果过期、重复使用或 state 校验失败，重新执行本节发起新的授权请求。如果拒绝 consent，回调会包含 OAuth 错误，上面的命令会停止，不再请求 token。

## 7. 携带 token 请求资源接口

在同一个终端执行：

```shell
curl -sS -H "Authorization: Bearer $QAS_ACCESS_TOKEN" \
  http://localhost:8080/api/messages
```

预期返回以下 JSON，字段顺序不影响结果：

```json
{"subject":"alice","message":"Hello, OAuth!"}
```

不带 token 时返回 `401`。token 认证成功但缺少所需的 `message.read` 权限时返回 `403`。

用户的角色和权限不会自动写入 token，也不会自动与客户端 scope 取交集。本例通过授予的 scope 控制 API 访问；业务需要限制用户可授权范围时，请提供相应的用户访问策略，参见[身份与权限](./identity-and-access)。

## 接入自己的应用

- [配置参考](/zh/reference/)：客户端设置、默认页面、端点路径与 CDI 替换点。
- [存储与密钥](./storage-and-keys)：持久化仓储、签名密钥，以及独立的 Quarkus Form 会话加密密钥。
- [Token 与资源服务器](./tokens-and-resources)：资源服务器独立部署、issuer/audience 校验与 claims 定制。
- [Authorization Code + PKCE](./authorization-code)：进阶阅读，使用 PKCE 的 public Vue 客户端、OIDC 与登出。[仓库示例](https://github.com/flynndi/quarkus-authorization-server/tree/main/examples)可作为可选的完整运行参考。
- [Client Credentials](./client-credentials)：无需用户登录的机器间调用。

部署时使用 HTTPS 和实际的 issuer、回调地址，替换演示凭据，配置持久化密钥和存储。将两个服务器分开部署不会改变这条流程：资源服务器的 `quarkus.oidc.auth-server-url` 指向授权服务器即可。
