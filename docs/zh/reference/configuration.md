# 服务端配置

扩展属性统一使用 `quarkus.authorization-server` 前缀，下表省略这一前缀。可写在 `application.properties` 中，或添加 `quarkus-config-yaml` 后使用 `application.yaml`。外部值通过 Quarkus Config 提供；应用行为与仓储通过 CDI 提供。

客户端和密码学相关设置见[注册客户端](./clients)、[签名密钥](./signing)和 [DPoP](./dpop)。

## 配置阶段 {#phases}

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 阶段 | 修改如何生效 | 源码 |
| --- | --- | --- |
| `BUILD_TIME` | 重新构建应用，决定安装哪些路由和 Bean。 | [AuthorizationServerBuildTimeConfig][build-config] |
| `BUILD_AND_RUN_TIME_FIXED` | 重新构建应用；运行时代码可读取，但值在构建时固定。 | [AuthorizationServerOidcConfig][oidc-config]、[AuthorizationServerClientRegistrationConfig][registration-config] |
| `RUN_TIME` | 启动应用时提供，无需重新构建；不代表支持热刷新。 | [AuthorizationServerRuntimeConfig][runtime-config] |

</div>

每节标注的阶段适用于该节所有属性。默认值标记为**未设置**表示映射没有值，条件性必填要求另行说明。Quarkus HTTP、TLS、Form 与数据源属性由对应扩展管理。

## 构建期开关 {#switches}

阶段：`BUILD_TIME`。源码：[AuthorizationServerBuildTimeConfig][build-config]。

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 属性 | 类型 / 默认值 | 行为 |
| --- | --- | --- |
| `enabled` | boolean · `true` | 安装授权服务器端点与安全组件；设为 `false` 禁用扩展的构建步骤。 |
| `multiple-issuers-allowed` | boolean · `false` | 启用按路径选择 issuer；需要运行期 `issuers` 与 tenant CDI Bean，见[多 issuer](#multiple-issuers)。 |
| `default-login-page-enabled` | boolean · `false` | 安装登录/错误页及浏览器端点的 Form 选择，提供可覆盖的宿主 Form 默认值。要求 `quarkus.http.auth.form.enabled=true`，用户身份仍由应用提供。见[浏览器登录](#browser-login)。 |
| `pushed-authorization-requests-enabled` | boolean · `false` | 安装 PAR 端点并在 metadata 中发布，不强制所有客户端使用 PAR。 |

</div>

没有每种 grant 的独立开关。客户端的 `authorization-grant-types` 决定它可以使用哪些已安装的 grant。

## 浏览器登录 {#browser-login}

扩展开启时，通过两个构建期开关启用内置登录集成：

```properties
quarkus.authorization-server.default-login-page-enabled=true
quarkus.http.auth.form.enabled=true
```

扩展不会隐式开启 Quarkus Form。只开启内置页面而不启用 Form，会在构建时失败。这两个开关只装配登录集成，客户端、用户 IdentityProvider、issuer 和资源服务器配置仍由应用负责；固定签名 PEM 不是其前置条件，见[临时与固定密钥](./signing#single-key)。

扩展、内置页面和 Quarkus Form 都开启时，扩展为登录/错误页、Form 提交地址、授权、设备确认和（启用 OIDC 时）登出端点选择 Form。各端点原有授权策略继续生效：初始授权请求先校验后登录；consent 提交和设备确认要求用户身份；登出允许匿名进入协议校验。UserInfo、客户端认证和资源 API 沿用自己的认证机制。

页面和提交地址遵循 Quarkus Form 的服务器绝对路径语义；协议路径遵循 HTTP root、自定义端点和 issuer 前缀。默认页面处理器只渲染 GET，选择 Form 不会增加其他页面方法。

| Form 属性（前缀 `quarkus.http.auth.form.*`） | 内置模式下的缺省值 |
| --- | --- |
| `login-page`、`error-page`、`post-location` | Quarkus 默认值：`/login.html`、`/error.html`、`/j_security_check` |
| `landing-page` | `${quarkus.http.auth.form.login-page}`；仅在没有待恢复请求时使用 |
| `http-only-cookie` | `true` |
| `cookie-same-site` | `lax` |

应用显式配置通过 Quarkus Config 覆盖这些值。Cookie 设置会影响宿主共用该 Form 机制的其他登录；Cookie 名称、有效期、路径、域及会话加密密钥继续由 Quarkus/应用配置。关闭内置页面后，本方案的额外装配和缺省值不再生效；应用自行提供页面时，也自行配置认证机制选择。

扩展提供的三个缺省值通过 `RunTimeConfigurationDefaultBuildItem` 装配，属于运行期值。仅改变内置页地址时，修改 Quarkus Form 页面属性即可；替换登录实现时则关闭内置模式，并显式配置应用需要的 Cookie 和 landing-page 设置。参见[自定义浏览器登录](/zh/guide/authorization-code#customize-browser-login)。

HTTP permission 遵循 Quarkus 的组合规则，不等同于普通配置值覆盖。精确浏览器路径可成为全站 `/*` 规则的例外；共享检查和匹配的方法限定检查继续生效。HTTP permission 配置在同一精确路径或匹配的共享规则中指定冲突机制时，启动失败并指出配置名称；重复选择 `form` 可以共存。该检查覆盖配置条目，不覆盖任意代码注册的 `HttpSecurity` observer 或自定义 policy，后者仍遵循 Quarkus 的顺序和匹配语义。

装配见 [AuthorizationServerProcessor][processor]；机制选择与冲突检查见 [BrowserLoginSecurityConfiguration](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/web/BrowserLoginSecurityConfiguration.java)；共享的页面路径解析见 [DefaultLoginPage](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/web/DefaultLoginPage.java)。

## 可选协议 {#optional-protocols}

阶段：`BUILD_AND_RUN_TIME_FIXED`。源码：[AuthorizationServerOidcConfig][oidc-config] 与 [AuthorizationServerClientRegistrationConfig][registration-config]。以下四项均为 boolean，默认均为 `false`。

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 属性 | 启用后的行为 |
| --- | --- |
| `oidc.enabled` | 启用 OpenID Connect Authorization Code 请求、discovery、UserInfo 与 Logout。客户端仍需对应的 scope 和 redirect；签名密钥集必须包含 RS256 私钥。 |
| `oidc.client-registration.enabled` | 安装受保护的 OIDC 客户端注册和配置读取接口，要求 `oidc.enabled=true`。 |
| `client-registration.enabled` | 安装独立的 OAuth 2.0 客户端注册，不依赖 OIDC。通常要求具有 `client.create` 的 initial access token。 |
| `client-registration.open-registration-allowed` | 允许不带 token 访问 OAuth 注册端点，仅在 `client-registration.enabled=true` 时生效，不开放 OIDC 注册。 |

</div>

启用注册不会自动确定客户端允许申请的 scope；应用通过注册 validator 指定策略，默认拒绝非空的请求 scope。即使开放 OAuth 注册，OIDC 注册仍受保护。

## 端点路径 {#endpoint-paths}

阶段：`BUILD_TIME`。以下类型均为 `String`，默认值见表。源码：[AuthorizationServerBuildTimeConfig][build-config]；校验：[EndpointPathConverter][path-converter]；路由安装：[AuthorizationServerProcessor][processor]。

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 属性 | 默认值 | 安装条件 |
| --- | --- | --- |
| `authorization-endpoint` | `/oauth2/authorize` | 扩展启用 |
| `token-endpoint` | `/oauth2/token` | 扩展启用 |
| `jwk-set-endpoint` | `/oauth2/jwks` | 扩展启用 |
| `token-introspection-endpoint` | `/oauth2/introspect` | 扩展启用 |
| `token-revocation-endpoint` | `/oauth2/revoke` | 扩展启用 |
| `device-authorization-endpoint` | `/oauth2/device_authorization` | 扩展启用 |
| `device-verification-endpoint` | `/oauth2/device_verification` | 扩展启用 |
| `pushed-authorization-request-endpoint` | `/oauth2/par` | PAR 启用 |
| `client-registration-endpoint` | `/oauth2/register` | OAuth 注册启用 |
| `oidc-client-registration-endpoint` | `/connect/register` | OIDC 和 OIDC 注册均启用 |
| `oidc-user-info-endpoint` | `/userinfo` | OIDC 启用 |
| `oidc-logout-endpoint` | `/connect/logout` | OIDC 启用 |

</div>

路径必须以 `/` 开头，不能是空白、单独的 `/`、以 `//` 开头，或包含 `?`、`#`。路径位于 `quarkus.http.root-path` 下，不是完整 URL。例如 root 为 `/server`、token 端点为 `/oauth2/token` 时，实际路径为 `/server/oauth2/token`。配置路径不会启用可选功能。已启用端点应选择不同路径；尤其 OAuth 与 OIDC 注册同时启用时，二者路径不能相同。

发现路径固定：OAuth metadata 把 `/.well-known/oauth-authorization-server` 放在 issuer 路径之前；OIDC discovery 在 issuer 后追加 `/.well-known/openid-configuration`。Form 登录与提交路径属于 Quarkus HTTP 配置，不在本表中；使用 HTTP root 时也要显式配置它们的服务器绝对路径。

构建阶段会检查扩展已启用的协议端点和固定 discovery 路由：有效路径重叠且占用相同 HTTP 方法时，报告冲突端点、配置项、路径和方法。检查使用 Quarkus 的 HTTP root 路径解析，并考虑多 issuer 前缀；关闭的可选端点不占用路径。仅 GET 的 JWKS 与仅 POST 的 token 端点可以共用路径；PAR 为返回 405 接管其路径上的所有方法，因此不能与 GET 端点共用路径。此诊断针对扩展的协议路由，不检查应用自定义路由或运行期 Form 登录页地址。实现：[EndpointValidationProcessor][endpoint-validation]。

## Issuer {#issuer}

阶段：`RUN_TIME`。映射：[AuthorizationServerRuntimeConfig][runtime-config]。校验：[AuthorizationServerRecorder][recorder] 与 [AuthorizationServerEndpoints][endpoints]。

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 属性 | 类型 / 默认值 | 要求 |
| --- | --- | --- |
| `issuer` | `String` · 未设置 | 单 issuer 在 normal 启动模式下必填；必须是有 host、没有 query/fragment 的绝对 HTTP(S) URL。多 issuer 模式不能设置。 |
| `issuers."<tenant-id>"` | `Map<String, String>` 条目 · 空 Map | 多 issuer 模式必填且非空，其他模式禁止使用。每个值为对外的规范 issuer URL。 |

</div>

填写外部可访问的 issuer，包括公开路径前缀。扩展不会根据 `Host` 或转发 header 推导规范 issuer。dev/test 允许省略单 issuer，但仍保持未设置，不会自动变成 `http://localhost:8080`。为了 discovery、JWT client assertion 和一致的 token claims，应明确配置。

```properties
quarkus.authorization-server.issuer=https://auth.example.com
```

### 多 issuer {#multiple-issuers}

```properties
quarkus.http.root-path=/server
quarkus.authorization-server.multiple-issuers-allowed=true
quarkus.authorization-server.issuers.alpha=https://auth.example.com/server/alpha
quarkus.authorization-server.issuers.beta=https://auth.example.com/server/beta
```

tenant ID 匹配 `[A-Za-z0-9_-]+`。每个 URL 使用 `http` 或 `https`、有 host、没有 user info/query/fragment；路径必须恰好等于 HTTP root 加 tenant ID，末尾不能带 `/`。上例 alpha 的 token 端点是 `/server/alpha/oauth2/token`，OAuth metadata 是 `/.well-known/oauth-authorization-server/server/alpha`。

每个 ID 必须对应一个可解析的 `AuthorizationServerTenant` CDI Bean，用 `@Identifier("<tenant-id>")` 标记，提供 client、authorization、consent 仓储和签名密钥源。各 tenant 不能复用同一仓储实例，应用还需保证数据隔离。未知 tenant 路径不会回退到其他 issuer。

此模式不能使用单 `issuer`、全局 `clients.*` 或全局签名密钥配置。端点后缀、协议开关和 DPoP 参数共享。修改构建期开关需要重建；修改运行期 issuer Map 和 tenant 数据，需要带着匹配的 CDI 组件重启，不是逐请求更新配置。

`AuthorizationServerContext` 解析当前请求的 issuer。启动或后台任务应直接使用具体 tenant 组件。

源码：[AuthorizationServerTenantRegistry][tenant-registry]。完整应用见[多 issuer 集成示例][integration-tests]。

[build-config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/deployment/src/main/java/io/quarkiverse/authorization/server/deployment/AuthorizationServerBuildTimeConfig.java
[oidc-config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/AuthorizationServerOidcConfig.java
[registration-config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/AuthorizationServerClientRegistrationConfig.java
[runtime-config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/AuthorizationServerRuntimeConfig.java
[path-converter]: https://github.com/flynndi/quarkus-authorization-server/blob/main/deployment/src/main/java/io/quarkiverse/authorization/server/deployment/EndpointPathConverter.java
[processor]: https://github.com/flynndi/quarkus-authorization-server/blob/main/deployment/src/main/java/io/quarkiverse/authorization/server/deployment/AuthorizationServerProcessor.java
[recorder]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/AuthorizationServerRecorder.java
[endpoints]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/tenant/AuthorizationServerEndpoints.java
[tenant-registry]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/tenant/AuthorizationServerTenantRegistry.java
[integration-tests]: https://github.com/flynndi/quarkus-authorization-server/tree/main/integration-tests/authorization-code/src/main/java/io/quarkiverse/authorization/server/it/multipleissuers

[endpoint-validation]: https://github.com/flynndi/quarkus-authorization-server/blob/main/deployment/src/main/java/io/quarkiverse/authorization/server/deployment/EndpointValidationProcessor.java
