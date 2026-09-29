# Authorization Code + PKCE

浏览器应用需要用户登录并授权访问 API 时，使用这条流程。Vue 应用是 public OAuth client：持有 client ID，使用 S256 PKCE，不保存 client secret。

## 运行示例

[快速开始](./getting-started)从依赖创建独立的授权服务器与资源服务器应用，走通登录、使用 client secret 兑换授权码与访问受保护接口。本篇通过可选的 [Vue 示例](https://github.com/flynndi/quarkus-authorization-server/tree/main/examples/authorization-code)为 public 客户端引入 PKCE。该 Vue 示例为方便运行，在一个后端中同时承载授权服务器和资源 API。在仓库根目录启动后端：

```shell
./gradlew :examples:authorization-code:quarkusDev --no-parallel
```

另开终端启动前端：

```shell
cd examples/authorization-code/frontend
npm ci
npm run dev
```

打开 `http://localhost:5173/`，使用 `resource-owner` / `resource-owner-password` 登录。下文的 client ID、回调与账号属于该示例，与快速开始中的配置不同。

| 设置 | 示例值 |
| --- | --- |
| Issuer | `http://localhost:8080` |
| Client ID | `authorization-code-public-client` |
| 客户端认证 | `none` |
| Grant | `authorization_code` |
| Redirect URI | `http://localhost:5173/callback` |
| 退出后跳转 | `http://localhost:5173/` |
| 请求 scope | `openid profile message.read` |

[`AuthorizationServerPersistence`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/src/main/java/io/quarkiverse/authorization/server/example/authorizationcode/authorizationserver/config/AuthorizationServerPersistence.java) 注册这个客户端，显式要求 PKCE 和 consent。示例启用 OIDC，用于发现、UserInfo 和退出登录。

## 一次请求如何完成

1. `oidc-client-ts` 生成 state 和 PKCE verifier，携带 S256 challenge 跳转到授权端点。
2. 扩展先校验授权请求，再让 Quarkus Form 对未登录用户发起登录挑战。
3. 默认登录页向 `/j_security_check` 提交凭据。Quarkus 验证用户、设置加密的 Form Cookie，并恢复原授权 URL。
4. 需要 consent 时，扩展显示确认页。用户在授权服务器上选择 scope 并批准，或拒绝请求。
5. 浏览器带 code 和 state（或 OAuth 错误）回到注册的 callback。客户端校验 state，携带 code 和 verifier 到 token 端点兑换。
6. Vue 携带 access token 调用 `/api/messages`。`quarkus-oidc` 验证 token，API 要求 `message.read`。

客户端实现见 [`client.js`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/frontend/src/client.js)。Token 只保存在内存；临时授权事务使用 `sessionStorage`。

## 分开浏览器登录和 API 认证

开启内置页面和 Quarkus Form，扩展自动为自己的浏览器端点选择 Form；应用保留 API 认证规则：

其中仅 `default-login-page-enabled` 和 `quarkus.http.auth.form.enabled` 用于启用浏览器登录。下面的 OIDC 开关和资源 permission 分别用于这个示例的 OIDC 流程与 Bearer API 隔离。

```yaml
quarkus:
  authorization-server:
    default-login-page-enabled: true
    oidc:
      enabled: true
  http:
    auth:
      form:
        enabled: true
      permission:
        resources:
          paths: /api/*
          policy: authenticated
          auth-mechanism: Bearer
```

默认提供 `/login.html`、`/error.html`，表单提交到 `/j_security_check`，不必再写 login、authorization 的 permission 条目。同一集成也为设备确认和已启用的 OIDC logout 选择 Form，不会因此将端点改为公开访问或改变协议校验。

如需保留示例的 `/auth/login`，保持内置页面开启，再添加以下配置即可：

```properties
quarkus.http.auth.form.login-page=/auth/login
quarkus.http.auth.form.error-page=/auth/login?error=true
```

开启内置页面后，Form 缺省使用 HttpOnly、SameSite=Lax Cookie，登录落点跟随 `login-page`；应用显式提供的 Quarkus 配置可覆盖这些值。这些设置作用于宿主共用的 Form 机制，不是独立的 OAuth Cookie。冲突规则和自定义登录集成见[浏览器登录配置](/zh/reference/configuration#browser-login)。

这是配置节选，不是完整应用。Issuer、密钥、Cookie 有效期、CORS 与资源端配置见[完整示例](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/src/main/resources/application.yml)。应用仍需提供注册客户端和[用户 IdentityProvider](./identity-and-access)。本地演示不强制配置固定签名 PEM：完全不配置 `signing` 时，默认密钥源生成临时 RSA 密钥。持久部署自行提供签名密钥和 Form 会话加密密钥，两者职责不同。

扩展选择 Form，但仍允许初始授权请求先进入协议校验。Consent POST 继续要求已认证身份并校验 state。应用如果把所有 authorize 请求配置为 `authenticated`，登录挑战仍会早于协议校验，包括 OIDC `prompt=none` 请求。

## 自定义浏览器登录 {#customize-browser-login}

可以直接使用内置默认值，也可以按应用需要配置 Quarkus Form：

- **默认页面与 Cookie**：两个登录开关即可为浏览器端点选择 Form，默认提交地址、HttpOnly、SameSite 和 landing-page 无需在应用配置中重复声明。
- **自定义属性**：按需配置页面路径、Cookie 有效期、landing page 和 `quarkus.http.auth.session.encryption-key`，显式值覆盖默认值。
- **HTTP 权限**：配置资源 API 的 Bearer 规则和应用自有权限检查，浏览器机制选择由扩展提供。启动时若报告 `auth-mechanism` 冲突，检查指明的精确路径或 shared permission，使用内置集成时该处应选择 Form。
- **应用自有登录**：关闭 `default-login-page-enabled`，自行提供页面、认证机制选择及所需的 Form 属性。

只改变页面 URL 不需要新增页面 Bean；替换登录实现则需要自行提供集成，关闭内置模式会一并移除其机制选择与三个额外缺省值。通过页面 SPI 替换 consent 或设备确认渲染，与这个开关相互独立。

## 接入自己的应用

- 按[身份与权限](./identity-and-access)实现用户查询和认证。登录及 consent 仍在授权服务器上完成；前端负责 OAuth callback。
- 精确注册前端 callback 和退出地址。示例在客户端注册代码中写明这些常量，仅修改 `demo.frontend-url` 不会更新它们。
- 前端 `VITE_AUTHORITY` 与后端 `issuer` 使用同一个公开授权服务器 URL；`demo.frontend-url` 设置为前端 origin，供 CORS 使用。
- 对外部署使用 HTTPS。浏览器调用 API 时发送 access token，不跨源携带 Form Cookie。更换域名时也需检查 Cookie 和重定向配置。

## 刷新与退出

这个演示客户端只注册了 authorization-code grant。Vue 关闭自动静默续期；刷新页面后内存 token 丢失，再次发起授权。

更一般地说，当前服务器只在配置了相应 DPoP 流程及 refresh grant 时向 public client 签发 refresh token；confidential client 可以使用普通刷新流程。仅声明 `refresh_token` 不会让这个 public Bearer client 获得 refresh token。

OIDC logout 使用 ID Token 作为 `id_token_hint`，清理浏览器会话并返回注册的退出地址，不自动撤销已有 access token 或删除历史 consent。见[其他授权流程](./other-grants)和 [Token 与资源服务器](./tokens-and-resources)。

初始请求、consent 和 PAR 的准确参数见 [OAuth 端点](/zh/reference/endpoints)，UserInfo 与 logout 见 [OIDC 与注册](/zh/reference/oidc-and-registration)。
