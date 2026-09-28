# 介绍

Quarkus Authorization Server 是一个 Quarkus 扩展，在应用进程内提供 OAuth 2.0 授权服务器，并可按需打开 OpenID Connect。它通过 Quarkus 的 CDI、HTTP Security、`SecurityIdentity`、Vert.x 和构建期装配集成。

依赖坐标是 `@EXTENSION_GROUP@:quarkus-authorization-server:@EXTENSION_VERSION@`。本文档介绍扩展的配置方式，以及本仓库 `examples` 目录下各示例应用的运行方法。

## 它解决什么问题

应用需要签发 access token、校验客户端、可选地让浏览器用户登录并确认 scope。扩展负责协议端点、授权记录、token 生成和默认登录/consent HTML。应用负责：

- 用户模型，以及 Form 密码登录与 Cookie 恢复用的 `IdentityProvider`
- 客户端与授权存储（默认内存，或通过 CDI 换成 JDBC）
- 生产环境的 issuer、签名密钥和数据库迁移
- 资源 API 如何解释 token 里的 scope、角色和 claims

用户 roles/permissions、client scope 和资源端授权不是自动等价的，也不会互相继承。

## 和 Quarkus 怎么接

- 消费模块是 `runtime`，构建期装配在 `deployment`。
- 协议路由由 `RouteBuildItem` 安装，走 Vert.x handler，不是 Quarkus REST。
- OAuth 客户端认证进入 `IdentityProviderManager`，结果以 `SecurityIdentity` 传递。
- 同时启用内置登录页和 Quarkus Form 后，扩展装配浏览器机制选择及可覆盖的 Form 缺省值；用户认证仍使用应用的 Provider。
- 同步协议工作在 worker 上执行，HTTP adapter 不把 `RoutingContext` 传进领域服务。
- 若资源服务器使用 `quarkus-oidc`，它可以发现同一 issuer 的 metadata 和 JWKS。

模块边界和请求链见本站[架构指南](./architecture)，实现限制见[协议能力与边界](/zh/reference/protocol-support)。

## 已经实现的能力

| 能力 | 行为摘要 |
| --- | --- |
| Authorization Code | S256 PKCE、consent、登录前协议预校验；打开 OIDC 后支持 `prompt=none` |
| Refresh Token | 可收窄 scope；public client 在未使用 DPoP 时不会得到 refresh token |
| Client Credentials | 以 client 为主体，只签发 access token |
| Device Authorization | 用户必须明确确认设备；已有 consent 不会自动批准 |
| Token Exchange | 本机 active subject/actor token，不做外部 issuer 联邦 |
| Password | 基于密码的 grant，走应用的 Quarkus 用户认证 |
| Token 与 metadata | JWT 或 reference、JWKS、Introspection、Revocation、OAuth metadata |
| 客户端认证 | Basic、POST、`private_key_jwt`、`client_secret_jwt`、两种 mTLS、public `none` |
| OIDC | Discovery、UserInfo、带 `id_token_hint` 的 RP-Initiated Logout |
| DPoP | 默认支持，客户端可选使用；在支持的授权流程中验证 proof 并绑定 token |
| PAR / 动态注册 / 多 issuer | 按需配置；metadata 只反映已经安装的能力 |

支持的能力与边界见下文及各协议指南，以源码、公开 SPI 和测试为准。

## 应用需要写哪些代码

最短的机器客户端路径通常包括：注册一个 `client_credentials` 客户端、配置 issuer、提供受保护资源。本地演示可让默认密钥源自动生成临时签名密钥；持久密钥属于部署选择，见[签名密钥](/zh/reference/signing)。

浏览器 Code + PKCE 路径还要提供用户 `IdentityProvider`，并让前端作为 OAuth 客户端处理 callback。设置 `quarkus.authorization-server.default-login-page-enabled=true` 和 `quarkus.http.auth.form.enabled=true` 后，内置登录集成为扩展的浏览器端点选择 Form。登录和 consent 继续使用授权服务器页面，资源 API 的访问规则仍由应用保留。配置和自定义方式见 [Code 指南](./authorization-code)。

不要把 `integration-tests` 里的整套测试 fixture（公开口令、固定 PEM、H2 建表）当作生产装配。那些账号和密钥只用于演示与验收。

## 接下来

1. [快速开始](/zh/guide/getting-started)：在自己的应用中引入依赖，提供 CDI 用户认证，配置 YAML，登录并携带 token 调用 `quarkus-oidc` 资源接口。
2. [参考](/zh/reference/)：查配置键和后续端点/SPI 手册的入口。
3. [Playground](/zh/playground/)：连接 Quarkus 演示服务器体验四种授权流程、查看 Token 并调用资源 API，也可使用离线 PKCE、JWT 和请求工具。

## 按场景阅读

| 你要做什么 | 指南 |
| --- | --- |
| 浏览器登录并调用 API | [Authorization Code + PKCE](./authorization-code) |
| 机器客户端调用 API | [Client Credentials](./client-credentials) |
| 查看设备、刷新、交换与密码流程 | [其他授权流程](./other-grants) |
| 接入用户库，区分 scope 与权限 | [身份与权限](./identity-and-access) |
| 定制 claims，验证资源请求 | [Token 与资源服务器](./tokens-and-resources) |
| 保存授权数据并提供持久密钥 | [存储与签名密钥](./storage-and-keys) |
