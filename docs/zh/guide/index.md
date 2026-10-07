# 介绍

**实验性 · 社区维护**

OAuth2 and OpenID Connect Server Extension 提供构建 OAuth 2.0 授权服务器的组件，可按需启用 OpenID Connect。项目由社区贡献者维护，不由 Quarkus 项目或团队提供和维护。开发与安全审查仍在持续进行。

## 适合谁使用

本扩展面向**有经验、选择自行构建并维护授权服务的团队**，适用于新建或已有系统。这些团队自行管理用户与认证，需要向客户端应用授权，并愿意承担协议行为评估、安全审查与服务运行的责任。

应用如果只需要用户登录或 API 保护，应先考虑成熟的 OAuth/OIDC Provider 与 Quarkus Security。自行构建授权服务器需要另外承担开发与维护工作。

例如，一个系统拥有自己的用户服务和消息 API，另一个应用希望在用户同意后读取消息。用户在授权服务器登录并同意授予 `message.read`，客户端应用取得 access token，再携带它调用消息 API。客户端无需获得用户密码、直接访问用户库或共享授权服务器的登录 Cookie。

## 登录、授权与 API 访问

示例中的 Quarkus Form 负责用户在授权服务器上的本地登录。扩展使用该身份处理授权请求、获取 consent 并签发 token。仅完成 Form 登录，并不会赋予另一个客户端应用调用 API 的权限。

| 场景 | 流程 | 客户端得到什么 |
| --- | --- | --- |
| 应用代表自己访问 API | Client Credentials | 代表客户端的 access token，无需用户登录 |
| 应用经用户同意访问 API | Authorization Code | 用于已授权访问的 access token |
| 用户通过 OpenID Provider 登录客户端应用 | 带 `openid` 的 OIDC Authorization Code | 描述用户认证结果的 ID Token，以及 access token |

调用 API 使用 **access token**。**ID Token** 向 OIDC 客户端描述用户认证结果，不是资源 API 的访问凭据。

## `quarkus-oidc` 承担什么职责 {#oidc-roles}

本扩展实现授权服务器 / OpenID Provider（AS/OP）一侧。OAuth/OIDC 客户端与资源服务器各有职责：

| 角色 | 当前示例中的实现 |
| --- | --- |
| 授权服务器 / OpenID Provider | 本扩展处理协议端点与 token 签发；应用提供用户认证 |
| OAuth/OIDC 客户端（OIDC 登录时为 RP） | 快速开始用浏览器和终端演示 OAuth；Vue 示例使用 `oidc-client-ts` 完成 OIDC Authorization Code + PKCE |
| 资源 API | `quarkus-oidc` 的 `application-type=service` 验证 Bearer access token；API 执行自己的访问规则 |

`quarkus-oidc` 还支持 `application-type=web-app`，此时它作为 OIDC 客户端驱动授权码登录，与 Bearer 验证是不同的职责。当前 Vue 示例由 `oidc-client-ts` 驱动登录，没有验证 Quarkus `web-app` 这条集成路线。参见 [Quarkus 授权码指南](https://quarkus.io/guides/security-oidc-code-flow-authentication/)与[示例角色说明](./authorization-code#client-and-resource-server-roles)。

授权服务器应用提供 AS/OP 端点不需要依赖 `quarkus-oidc`。资源 API 必须验证 token，本项目的 Quarkus 示例使用 `quarkus-oidc` 完成验证；协议也允许使用其他兼容库实现客户端与资源服务器。

[快速开始](./getting-started)将授权服务器与资源 API 运行在**两个独立应用**中，通过 issuer discovery、公钥和 access token 建立信任关系。将授权服务器作为独立服务构建和运行；资源 API 不需要该扩展或用户密码库。扩展运行在承载授权服务的 Quarkus 应用内部。

## 应用需要提供什么

扩展负责协议端点、授权记录、token 生成及默认登录/consent 页面。应用负责：

- 用户模型与认证；快速开始通过 `IdentityProvider` Bean 将其接入 Form 登录
- 客户端注册，以及客户端、授权记录、consent 的存储（默认内存，也可通过 CDI 使用 JDBC）
- 部署使用的 issuer、持久签名密钥与数据库迁移
- 资源 API 如何解释 scope、角色和 claims

用户 roles/permissions、client scope 和资源端授权不是自动等价的，也不会互相继承。扩展提供构建授权服务器所需的组件，并不包含完整的用户管理产品。

从在授权服务器应用中引入 `@EXTENSION_GROUP@:quarkus-authorization-server:@EXTENSION_VERSION@` 开始。[快速开始](./getting-started)依次介绍依赖、用户 Bean、两个应用各自的 YAML 配置，以及授权码、token 和 API 调用的完整流程，无需下载本仓库源码。

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

## 接下来

1. [快速开始](/zh/guide/getting-started)：独立运行授权服务器与资源 API，通过 Authorization Code 获取 token，再携带 token 调用 API。
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
