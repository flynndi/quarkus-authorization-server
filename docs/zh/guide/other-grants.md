# 其他授权流程

浏览器客户端从 [Authorization Code + PKCE](./authorization-code) 开始，机器客户端从 [Client Credentials](./client-credentials) 开始。扩展还实现了以下流程，客户端的 `authorization-grant-types` 决定它能使用哪些 grant。

## Device Authorization

设备先申请 device code 和 user code。用户在浏览器打开确认 URL，登录并批准；设备按响应中的间隔轮询 token 端点，取得 access token 后访问 API。

```shell
./gradlew :examples:device-authorization:quarkusDev --no-parallel
```

[设备示例源码](https://github.com/flynndi/quarkus-authorization-server/tree/main/examples/device-authorization)注册的客户端是 `public-device`，演示用户是 `resource-owner` / `resource-owner-password`，token grant 为 `urn:ietf:params:oauth:grant-type:device_code`。

浏览器确认与 Authorization Code 共用[内置登录集成](/zh/reference/configuration#browser-login)。开启默认页面和 Quarkus Form 后，扩展为确认 GET/POST 选择 Form，并保留必须有用户身份的要求，无需再写独立的设备确认机制规则。设备申请授权和获取 token 的请求仍使用 OAuth 客户端认证。

批准前返回 `authorization_pending`，轮询过快可能返回 `slow_down`。访问确认页 GET 或用户过去授予过 consent，都不会批准新设备请求，必须由用户显式确认。

## Refresh Token

Refresh 延续已有授权。客户端必须注册 `refresh_token`，授权记录必须包含属于该客户端且仍有效的 refresh token。请求 scope 可以收窄原授权，不能扩大范围。

默认复用 refresh token；把客户端 `reuse-refresh-tokens=false` 可改为轮换，成功替换后的旧 token 再提交会得到 `invalid_grant`。Public client 要求已有 DPoP key binding 及匹配 proof，confidential client 可以使用普通刷新认证。

这不是一次新用户登录。服务使用授权记录里的身份，不会自动重新查询角色。见 [`RefreshTokenGrant`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/refreshtoken/RefreshTokenGrant.java)和[身份与权限](./identity-and-access)。

## Token Exchange

Token Exchange 使用 `urn:ietf:params:oauth:grant-type:token-exchange`，根据 subject token 换取新的 access token；委托场景还可携带 actor token。当前服务从本 issuer 的授权仓储查询有效 token，不是外部 issuer 联邦网关。

实现支持 JWT/reference 表示和 actor 链 claims。此流程使用 DPoP 时绑定的是输出 token，不验证或继承输入 subject/actor 的 DPoP 绑定，也不签发 refresh token。

高级 fixture 与 HTTP 测试位于 [`integration-tests/token-exchange`](https://github.com/flynndi/quarkus-authorization-server/tree/main/integration-tests/token-exchange)，协议逻辑见 [`TokenExchangeGrant`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/tokenexchange/TokenExchangeGrant.java)。用 fixture 理解接口即可，不应把含测试专用端点的应用直接当作公开演示后端。

## Password

项目额外实现 `grant_type=password`：客户端向 token 端点提交用户密码，应用提供 `IdentityProvider<UsernamePasswordAuthenticationRequest>`。

```shell
./gradlew :examples:password-grant:quarkusDev --no-parallel
```

[Password 示例源码](https://github.com/flynndi/quarkus-authorization-server/tree/main/examples/password-grant)包含客户端注册、演示用户和资源 API。这条流程没有浏览器 Form Cookie 恢复步骤，因此仅为这个 grant 不需要 Trusted provider。Password 不支持 DPoP，携带 DPoP header 会被拒绝。本站的浏览器应用使用 Code + PKCE。

## 去哪里运行

四个简单应用在 `examples`；协议异常、Token Exchange 与高级互操作验证在 `integration-tests`。使用默认 8080 端口时，先停止当前示例再启动下一个。

[Playground](/zh/playground/) 后续会接入单独提供的 Quarkus 演示后端，覆盖全部已支持 grant。接通前先运行本地示例；静态文档站本身不签发 token。

完整 grant 参数表见 [OAuth 端点](/zh/reference/endpoints#token-grants)，当前限制见[协议能力与边界](/zh/reference/protocol-support)。
