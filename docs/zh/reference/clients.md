# 注册客户端

前缀：`quarkus.authorization-server.clients."<client-id>"`。本页所有属性均为 **`RUN_TIME`**，在应用启动时提供；修改无需重新构建，也不会更新已经运行的仓储。

Map key 是 OAuth `client_id`，默认没有配置客户端。每个条目初始化到默认 `InMemoryRegisteredClientRepository`。应用的 CDI `RegisteredClientRepository` 会**完整替换默认仓储**，`clients.*` 不会自动导入或合并进去。多 issuer 模式使用 tenant 仓储，禁止全局 `clients.*` 配置。

源码：[RegisteredClientConfig][config]、[RegisteredClientRepositoryProducer][producer] 与 [RegisteredClient.Builder][client]。表格列出此适配器产生的实际值，包含可选属性省略后应用的 Builder 默认值。

## 身份与凭据 {#identity}

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 属性 | 类型 / 默认值 | 要求或行为 |
| --- | --- | --- |
| `id` | `String` · Map key | 仓储内部 ID，不能是空白；与 `client_id` 不同。 |
| `client-name` | `String` · 内部 `id` | 显示名。省略或空白时回退到 `id`，而 `id` 默认是 Map key。 |
| `client-id-issued-at` | `Instant` · 未设置 | ISO-8601 instant，例如 `2026-01-01T00:00:00Z`；不会自动填写创建时间。 |
| `client-secret` | `String` · 未设置 | Basic、POST 和 HMAC 认证需要；保存格式取决于[认证方式](#authentication)。 |
| `client-secret-expires-at` | `Instant` · 未设置 | ISO-8601 instant；Basic/POST/HMAC 拒绝过期 secret，省略表示未配置过期时间。 |
| `client-authentication-methods` | `Set<String>` · `client_secret_basic` | 显式登记客户端实际使用的方式，见下表。 |

</div>

### 认证方式 {#authentication}

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 方式 | 注册时需要的材料 |
| --- | --- |
| `client_secret_basic`、`client_secret_post` | 使用默认 `ClientSecretVerifier` 时，`client-secret` 保存 bcrypt hash；客户端提交原始 secret。 |
| `client_secret_jwt` | `client-secret` 保存原始 UTF-8 共享密钥，并显式指定 HS256、HS384 或 HS512 assertion 算法；bcrypt hash 不能代替 HMAC 密钥。 |
| `private_key_jwt` | `jwk-set-url` 与显式 RS/PS/ES assertion 算法，不需要 client secret。 |
| `tls_client_auth` | `x509-certificate-subject-dn` 以及宿主应用的 TLS 证书校验，不需要 client secret。 |
| `self_signed_tls_client_auth` | `jwk-set-url`，对应 JWK 需包含 `x5c`，不需要 client secret。 |
| `none` | Public client，不需要 client secret；Authorization Code 兑换仍要求 PKCE。 |

</div>

使用默认 bcrypt verifier 时，Basic/POST 与 `client_secret_jwt` 应分开注册客户端，因为保存的 secret 格式不同。配置加载不会替你编码明文 secret。mTLS 使用真实 TLS peer 证书，不使用转发 HTTP header；宿主应用负责 TLS 配置。

这些要求由认证路径执行，并非全部由启动时的配置映射校验。成功加载 client 条目不等于它可以成功认证。

源码：[BcryptClientSecretVerifier][secret-verifier]、[JwtClientAssertionVerifier][assertion-verifier] 与 [X509ClientCertificateAuthenticationProvider][x509-provider]。

## Grant、redirect 与 scope {#grants}

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 属性 | 类型 / 默认值 | 要求或行为 |
| --- | --- | --- |
| `authorization-grant-types` | `Set<String>` · 必填 | 不能为空。内建值见下文；自定义值不会安装 `GrantHandler`。 |
| `redirect-uris` | `Set<String>` · 空集合 | 使用 `authorization_code` 时必填；注册时拒绝非法 URI 语法和 fragment，授权请求执行 redirect 匹配，包括 loopback 端口规则。 |
| `post-logout-redirect-uris` | `Set<String>` · 空集合 | 可选。注册时拒绝非法 URI 语法和 fragment，Logout 要求与注册值完整匹配。 |
| `scopes` | `Set<String>` · 空集合 | 登记允许的 scope，不是用户角色。字符遵循 OAuth scope-token 语法：可打印 ASCII，但不包含空格、双引号和反斜杠。 |

</div>

内建 grant 值：`authorization_code`、`client_credentials`、`refresh_token`、`password`、`urn:ietf:params:oauth:grant-type:device_code`、`urn:ietf:params:oauth:grant-type:token-exchange`。适用边界见[其他授权流程](/zh/guide/other-grants)。登记 `refresh_token` 不保证每种流程都会签发 refresh token；普通 public Bearer Authorization Code client 不会获得 refresh token。

以上是静态配置注册的属性。动态注册有独立的 parser、validator 和允许的 metadata，不是本表的 JSON 映射。

## ClientSettings 映射 {#client-settings}

源码：[ClientSettings][client-settings]，由 [RegisteredClientRepositoryProducer][producer] 应用。以下条目仍使用同一客户端前缀，阶段均为 `RUN_TIME`。

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 属性 → Builder 方法 | 类型 / 实际默认值 | 约束或用途 |
| --- | --- | --- |
| `require-proof-key` → `requireProofKey(...)` | boolean · `true` | 要求 S256 PKCE。Confidential client 可设为 `false`；public Code 兑换仍要求 PKCE。提供的 challenge 必须使用 S256。 |
| `require-authorization-consent` → `requireAuthorizationConsent(...)` | boolean · `false`；public Code client：`true` | 供 consent 策略使用；设为 `true` 不代表已同意的 scope 每次都显示页面。默认推导见下文。 |
| `jwk-set-url` → `jwkSetUrl(...)` | `String` · 未设置 | `private_key_jwt` 和 `self_signed_tls_client_auth` 必需；有 host、无 user info/fragment 的 HTTP(S) URL，发布的是**客户端**公钥。 |
| `x509-certificate-subject-dn` → `x509CertificateSubjectDN(...)` | `String` · 未设置 | `tls_client_auth` 必需；非空白 DN，使用 `X500Principal` 解析和比较。 |
| `token-endpoint-authentication-signing-algorithm` → `tokenEndpointAuthenticationSigningAlgorithm(...)` | `String` → `JwsAlgorithm` · 未设置 | JWT assertion client 必需：`private_key_jwt` 用 RS256/384/512、PS256/384/512、ES256/384/512；`client_secret_jwt` 用 HS256/384/512。拒绝未知名称。 |

</div>

`ClientSettings.builder()` 本身默认 PKCE 为 `true`、consent 为 `false`。没有显式提供 `ClientSettings` 时，`RegisteredClient.Builder` 为包含 `authorization_code` 且认证方式**仅有** `none` 的客户端推导 consent 为 `true`。配置注册先保留此推导，再应用显式覆盖值。自行提供 `ClientSettings` 时，值由应用负责，不会再次执行这一推导。

`ClientSettings.withSettings(map)` 复制已有设置，不补齐 Builder 默认值；它适合调整完整的设置对象，不能代替默认初始化。Public client 独立的 PKCE 要求见 [PkceVerifier][pkce]，URL 校验见 [ClientJwkSetCache][jwks]。

## TokenSettings 映射 {#token-settings}

源码：[TokenSettings][token-settings]，由 [RegisteredClientRepositoryProducer][producer] 应用。默认值来自 `TokenSettings.builder()`，不是每个客户端属性上的 `@WithDefault`。

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 属性 → Builder 方法 | 类型 / 实际默认值 | 约束或用途 |
| --- | --- | --- |
| `authorization-code-time-to-live` → `authorizationCodeTimeToLive(...)` | `Duration` · `PT5M` | 至少 1 秒；授权码有效期。 |
| `access-token-time-to-live` → `accessTokenTimeToLive(...)` | `Duration` · `PT5M` | 至少 1 秒；适用于 JWT 与 opaque access token。 |
| `device-code-time-to-live` → `deviceCodeTimeToLive(...)` | `Duration` · `PT5M` | 至少 1 秒；device code 和 user code 共用。 |
| `refresh-token-time-to-live` → `refreshTokenTimeToLive(...)` | `Duration` · `PT1H` | 至少 1 秒；签发 refresh token 时适用。 |
| `access-token-format` → `accessTokenFormat(...)` | `OAuth2TokenFormat` · `self-contained` | 默认 generator 支持 `self-contained`（JWT）和 `reference`（opaque，通过 introspection 查询）。 |
| `reuse-refresh-tokens` → `reuseRefreshTokens(...)` | boolean · `true` | 设为 `false` 时成功刷新会替换 refresh token，旧值后续返回 `invalid_grant`；不代表保证并发原子消费。 |
| `id-token-signature-algorithm` → `idTokenSignatureAlgorithm(...)` | `SignatureAlgorithm` · `RS256` | RS256/384/512、PS256/384/512 或 ES256/384/512；需要对应算法的签名私钥，仅改变 ID Token 签名。 |

</div>

TTL setter 校验 `Duration.getSeconds() > 0`，正数但不足 1 秒也会被拒绝。建议填写明确的 duration，如 `PT5M`、`PT1H`。`TokenSettings.withSettings(map)` 保留传入 Map，不初始化默认值。

`OAuth2TokenFormat` 是值对象，不是仅允许两个内建格式的枚举。自定义字符串仍需兼容的 generator；配置能解析不代表 token 格式已经实现。ID Token TTL 没有客户端配置属性，默认 [JwtGenerator][jwt-generator] 当前使用 30 分钟。

## 最小示例 {#examples}

使用默认 Basic 认证的机器客户端，环境变量中保存 bcrypt hash：

```properties
quarkus.authorization-server.clients.machine.client-secret=${MACHINE_CLIENT_SECRET_BCRYPT}
quarkus.authorization-server.clients.machine.authorization-grant-types=client_credentials
quarkus.authorization-server.clients.machine.scopes=message.read
```

使用默认推导的 PKCE 和 consent 设置的 public 浏览器客户端：

```properties
quarkus.authorization-server.clients.browser.client-authentication-methods=none
quarkus.authorization-server.clients.browser.authorization-grant-types=authorization_code
quarkus.authorization-server.clients.browser.redirect-uris=https://app.example.com/callback
quarkus.authorization-server.clients.browser.scopes=message.read
```

以上仅为客户端片段，需另外配置 [issuer](./configuration#issuer)、[签名密钥](./signing)和应用用户认证。浏览器流程见 [Authorization Code + PKCE](/zh/guide/authorization-code)。

[config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/AuthorizationServerRuntimeConfig.java
[producer]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/RegisteredClientRepositoryProducer.java
[client]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/client/RegisteredClient.java
[client-settings]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/settings/ClientSettings.java
[token-settings]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/settings/TokenSettings.java
[secret-verifier]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/client/BcryptClientSecretVerifier.java
[assertion-verifier]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/client/authentication/JwtClientAssertionVerifier.java
[x509-provider]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/client/authentication/X509ClientCertificateAuthenticationProvider.java
[pkce]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/exchange/PkceVerifier.java
[jwks]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/client/authentication/ClientJwkSetCache.java
[jwt-generator]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/token/JwtGenerator.java
