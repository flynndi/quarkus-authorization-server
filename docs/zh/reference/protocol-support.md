# 协议能力与边界

本文记录这一实验性扩展已实现的协议范围与已知限制，不声明已完全符合所有相关标准或已具备生产就绪条件。详细请求见 [OAuth 端点](./endpoints)和 [OIDC 与注册](./oidc-and-registration)，配置见[服务端配置](./configuration)。

## Grant 与认证 {#grants}

| 领域 | 已实现边界 |
| --- | --- |
| Code + PKCE | Code response；S256 PKCE、登录前协议校验、待确认 consent 和用户/client 绑定。无 implicit/hybrid response 实现。 |
| Client Credentials | 仅客户端 access token，不发 refresh token。请求 scope 对照 client 检查，不是用户角色。 |
| Refresh | 需要已有 authorization 和 client，scope 可缩小。Public client 限制见下文。 |
| Device | 生成 device/user code、浏览器确认、token 轮询。无内置轮询限速或 `slow_down`。 |
| Password | 项目提供的兼容 grant，使用 Quarkus 用户认证；不是推荐浏览器登录方式，也不声明与 SAS grant 一致。 |
| Token Exchange | 有效的本地 subject/actor token、用户 subject 和委托校验、输出 token 生成。不是通用外部 token 信任联邦。 |
| 客户端认证 | Basic、POST、私钥 JWT、secret JWT、mTLS/self-signed mTLS 和 public 标识。TLS 客户端认证不增加证书绑定 access token。 |

分发与校验见 [OAuth2TokenEndpointHandler]、[TokenExchangeGrant] 和[客户端认证参考](./clients)。

## Token、refresh 与 DPoP {#tokens}

Generator 支持签名 JWT 和 opaque/reference access token，ID Token 为 JWT。Token scope 不会自动包含用户角色；通过 CDI 映射 claims，并在资源服务器执行权限判断。

Public Code client 不使用 DPoP 时可以获得 Bearer access token，但这条未绑定流程不发 refresh token。DPoP 绑定的 public Code 流程可以签发并使用相同 proof key 刷新。Confidential client 的 grant 允许时可普通 Bearer refresh；已绑定 refresh 仍需要匹配 key。轮换/复用由 `TokenSettings` 决定，不承诺 token-family 重放检测或并发轮换原子性。见 [OAuth2RefreshTokenGenerator] 和 [RefreshTokenGrant]。

DPoP 在支持的请求中可选使用，没有全局开启开关。Code、Refresh、Client Credentials、Device 和 Token Exchange 输出已实现 proof 验证、key 绑定、本地重放防护及算法发现。UserInfo 接受带资源 proof 的绑定 token。Password 拒绝 DPoP。Token Exchange 不验证或继承输入 token 的 DPoP 绑定。未实现服务端 nonce 签发或内置分布式 replay store。见 [DPoP 配置](./dpop)。

`quarkus-oidc` 资源服务器示例验证资源端互操作；授权服务器不配置其他应用的 token 校验。离线 JWT 校验不能即时反映数据库撤销状态。既有互操作 fixture 见[集成测试源码](https://github.com/flynndi/quarkus-authorization-server/tree/main/integration-tests)。

## 浏览器、OIDC 与 PAR {#browser-protocols}

| 领域 | 已实现边界 |
| --- | --- |
| 浏览器交互 | Quarkus HTTP 认证、可选默认 Form 登录页、可替换 consent/device 页面。没有内置 SPA 交互上下文 API 或托管用户库。 |
| `prompt=none` | 登录前校验；无法静默完成时返回 `login_required` / `consent_required`。不是完整 `prompt=login`、账号选择或重认证系统。 |
| OIDC | Code-flow ID Token、discovery、JSON UserInfo、基于 hint 的 RP-Initiated Logout、可选受保护注册。无签名/加密 UserInfo 或 front/back-channel logout。 |
| PAR | 可选认证 push、五分钟引用、已存储请求权威、普通授权仍可使用。无 JAR 或强制 PAR client 设置。 |
| 动态注册 | 独立 OAuth 与 OIDC 接口；仅 OAuth 可开放注册。需要明确 scope 策略，仅 OIDC 提供有限管理读取。无完整 client CRUD API。 |

应用 HTTP 策略可能阻止 authorize 执行匿名预校验。选择 Form mechanism 和保护 API 时遵循 [Code 指南](/zh/guide/authorization-code)；在 authorize 前放置笼统 `authenticated` 策略会改变 `prompt=none` 行为。

## 持久化、事务与多 issuer {#storage}

默认提供三个内存仓储，JDBC 实现通过 CDI 使用。Schema 创建/迁移和持久 client 初始化由应用负责。持久化身份是授权时快照，不是实时登录会话，也不是任意凭据/permission checker 的序列化。

JDBC 写操作在已加入 Agroal/JTA 事务时使用外部事务，否则每次写使用本地事务。扩展不开启整个 grant 或 registration 的事务。默认注册 client、保存 registration token 和消费 initial token 是分开的操作；并发单次消费 code/refresh/PAR 不保证原子性。`ProtocolExecutor` 提供 worker/request context 边界，不是事务边界。见[存储与签名密钥](/zh/guide/storage-and-keys)和 [JdbcTransactionSupport]。

Multiple issuers 使用有限配置 tenant 集合，并显式提供仓储和密钥。端点后缀、协议开关、TLS/DPoP 设置和应用策略 Bean 共享。Form 登录共享，OIDC session identifier 按 issuer 派生。这不是动态 tenant 创建或自动数据库行隔离。Registry 检查 bundle 选择和仓储对象分离，不检查数据库 schema。见 [AuthorizationServerTenantRegistry]。

## 验证范围 {#verification}

源码链接固定到本页核对的提交。既有 Java/JVM/native 结果有各自的范围和日期，编辑或构建文档不会重新执行它们。[Playground](/zh/playground/)单独标识哪些流程真正连接到在线后端；文档写明支持某项能力不等于对应演示已接通。

[AuthorizationServerTenantRegistry]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/tenant/AuthorizationServerTenantRegistry.java
[JdbcTransactionSupport]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/jdbc/JdbcTransactionSupport.java
[OAuth2RefreshTokenGenerator]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/token/OAuth2RefreshTokenGenerator.java
[OAuth2TokenEndpointHandler]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/web/OAuth2TokenEndpointHandler.java
[RefreshTokenGrant]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/refreshtoken/RefreshTokenGrant.java
[TokenExchangeGrant]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/tokenexchange/TokenExchangeGrant.java
