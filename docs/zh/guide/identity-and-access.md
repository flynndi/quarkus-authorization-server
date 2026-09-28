# 身份与权限

OAuth 请求可能同时涉及客户端和用户。即使授权服务器与资源 API 在同一个 Quarkus 进程里，也应区分这两种身份及其权限。

## 使用应用自己的用户模型

浏览器示例用自己的 `User` record 保存用户名、密码 hash、角色和权限，由 `UserService` 查询。扩展不要求专有的用户实体或用户表。

[`ResourceOwnerIdentityProviders`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/src/main/java/io/quarkiverse/authorization/server/example/authorizationcode/authorizationserver/config/ResourceOwnerIdentityProviders.java) 把该模型适配到两种 Quarkus 请求：

| 请求 | 使用时机 | Provider 的职责 |
| --- | --- | --- |
| `UsernamePasswordAuthenticationRequest` | Form 提交密码；Password grant 也使用它 | 查询用户、验证密码、构建 `SecurityIdentity` |
| `TrustedAuthenticationRequest` | 后续请求携带有效的 Quarkus Form Cookie | 根据可信 principal 查询用户，重建 `SecurityIdentity` |

两个 adapter 都属于授权服务器，共用同一个用户服务。Trusted 请求发生在 Form Cookie 验证之后，不是一个只接收用户名就允许登录的接口。

示例通过 `AuthenticationRequestContext.runBlocking` 校验密码，Trusted 查询目前是内存操作。若换成阻塞 JDBC 查询，也应通过认证请求上下文执行。其他 Quarkus 身份集成可能已经提供相应 Provider，不要重复注册同类实现。

源码：[`User`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/src/main/java/io/quarkiverse/authorization/server/example/authorizationcode/authorizationserver/user/User.java)、[`UserService`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/src/main/java/io/quarkiverse/authorization/server/example/authorizationcode/authorizationserver/service/UserService.java)。

## 资源端身份来自 token

访问 `/api/messages` 时，`quarkus-oidc` 验证 access token 并构建资源端 `SecurityIdentity`，不会调用上述两个用户 Provider。示例为 `/api/*` 显式选择 Bearer，授权服务器的 Form Cookie 不能认证这个 API。

Client Credentials 没有最终用户身份，subject 是注册客户端。Authorization Code 的 subject 是用户，而 OAuth 客户端按它注册的认证方式被独立认证或识别。

## Scope、角色与权限

| 概念 | 含义 | 校验位置 |
| --- | --- | --- |
| 客户端注册 scope | 客户端允许申请的范围 | 授权服务器 |
| 已授权 scope | 协议及策略检查后授予这次授权的范围 | Token 签发与资源端 scope 检查 |
| 用户 roles / permissions | 应用自己的用户权限模型 | 应用策略；显式映射 claim 后也可用于资源端策略 |
| 数据归属与业务规则 | 当前主体能否操作指定记录 | 资源 API |

客户端 scope 与任意用户 permission 不会自动求交。例如客户端注册了 `message.read`，只表示它可以申请这个 scope，不表示用户拥有全部消息。Consent 记录用户同意，不能替代业务授权。

默认 JWT generator 将已授权 scope 写入 `scope`。示例由 `quarkus-oidc` 将其映射为 permission，再使用 `@PermissionsAllowed("message.read")` 检查。若访问还依赖数据归属，资源端仍需校验具体记录。

Token 需要应用角色时，通过 [token customizer](./tokens-and-resources#添加应用-claim) 显式写入 claim，选择应传递的角色，不要序列化整个用户对象。`@RolesAllowed` 与 `@PermissionsAllowed` 表达不同检查，配置其中一个不会自动实现另一个。

## 授权后身份发生变化

授权记录可能保存历史 `SecurityIdentity`。JDBC 表示保留 principal、roles 和允许的协议属性，不持久化 credentials、任意 attributes 或 permission checkers。

因此刷新 token 不会自动重查当前用户角色和账号状态。业务要求立即失效或使用最新权限时，应结合用户服务及 token/资源检查实现对应策略。从授权记录复制的 claim 是快照，不是实时用户查询。

见 [`SecurityIdentityJacksonBuilder`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/jackson2/SecurityIdentityJacksonBuilder.java)和[存储与签名密钥](./storage-and-keys)。

默认实现、qualifier 和组合规则集中列在 [CDI 扩展点](/zh/reference/extensions)。
