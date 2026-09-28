# 签名密钥

前缀：`quarkus.authorization-server.signing`。本页所有属性均为 **`RUN_TIME`**，适用于默认 `ConfiguredAuthorizationServerKeySource`。启动时修改值无需重建，但 native classpath 资源必须已[包含在镜像中](#native-resources)；密钥加载不是热轮换 API。

映射：[SigningConfig 与 SigningKeyConfig][config]。加载和校验：[ConfiguredAuthorizationServerKeySource][source] 与 [AuthorizationServerKeyManager][manager]。

## 单密钥 {#single-key}

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 属性 | 类型 / 默认值 | 要求或行为 |
| --- | --- | --- |
| `algorithm` | `String` · `RS256` | 已配置的单密钥使用的算法，支持值见下文；仅设置它不会选择临时密钥的算法。 |
| `key-id` | `String` · 未设置 | 配置单密钥时必填且非空白，成为 JWT/JWK 的 `kid`。 |
| `private-key-location` | `String` · 未设置 | 单密钥配置必填，PKCS#8 private PEM。 |
| `public-key-location` | `String` · 未设置 | 单密钥配置必填，X.509 SubjectPublicKeyInfo public PEM。 |

</div>

提供 `key-id`、`private-key-location`、`public-key-location` 中任意一项即选择单密钥模式，三项都必须填写。三项都省略且 `keys` Map 为空时，密钥源生成临时 RSA-2048 密钥、RS256 算法和随机 `kid`，即使单独修改了 `algorithm` 也是如此。Normal 启动模式会记录警告；重启丢失该密钥，各实例独立生成不同密钥。

```properties
quarkus.authorization-server.signing.key-id=auth-key-1
quarkus.authorization-server.signing.algorithm=RS256
quarkus.authorization-server.signing.private-key-location=file:/run/secrets/auth-private-key.pem
quarkus.authorization-server.signing.public-key-location=file:/run/secrets/auth-public-key.pem
```

## 多密钥 {#multiple-keys}

`keys` Map 默认为空。条目名就是 `kid`，条目内部没有额外的 `key-id` 属性。

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 属性 | 类型 / 默认值 | 要求或行为 |
| --- | --- | --- |
| `active-key-id` | `String` · 未设置 | 要求存在 `keys`。超过一个条目时必填，必须指向含私钥的 key；只有一个条目时自动选择。 |
| `keys."<kid>".algorithm` | `String` · `RS256` | 此 key 的算法；Map key 不能是空白。 |
| `keys."<kid>".private-key-location` | `String` · 未设置 | 仅验签的 key 可省略；活动签名 key 必需。 |
| `keys."<kid>".public-key-location` | `String` · 未设置 | 每个条目必填，包含私钥的 key 也必须填写。 |

</div>

`keys.*` 不能与单密钥的 `key-id`、`private-key-location`、`public-key-location` 混用。顶层 `algorithm` 仅用于已配置的单密钥模式，Map 中每个条目使用各自的算法。

引入新的签名密钥时保留旧公钥：

```properties
quarkus.authorization-server.signing.active-key-id=current
quarkus.authorization-server.signing.keys.previous.public-key-location=file:/run/secrets/previous-public.pem
quarkus.authorization-server.signing.keys.current.private-key-location=file:/run/secrets/current-private.pem
quarkus.authorization-server.signing.keys.current.public-key-location=file:/run/secrets/current-public.pem
```

JWKS 端点发布所有已加载公钥。旧 token 仍有效时保留对应验签 key，并考虑资源服务器的 JWKS 缓存。这是重启时应用配置的轮换，不是自动定期轮换。

## Native 镜像资源 {#native-resources}

使用默认密钥源时，扩展会自动将构建时可见的 `classpath:` 公私钥资源加入 native 镜像。单密钥属性与 `keys."<kid>".*` 均适用，也包含仅用于验签的公钥。例如，配置 `private-key-location=classpath:keys/private.pem` 后，无需再在 `quarkus.native.resources.includes` 中重复声明。构建阶段只注册资源位置，密钥加载与校验仍在运行期执行。

收录范围由构建时生效的 profile 和可解析的配置表达式决定。仅在运行时提供的位置无法向已有可执行文件添加资源：应在构建时通过 `quarkus.native.resources.includes` 显式收录，或使用外部文件路径。普通路径及 `file:` 位置仍指向外部文件，不会自动打包。

应用提供的 `AuthorizationServerKeySource` 和多 issuer 的 tenant key source 仍自行管理资源。CDI 替换默认密钥源或启用多 issuer 时，不会自动打包未使用的默认签名配置。

## 格式与算法选择 {#algorithms}

Location 支持 `classpath:keys/key.pem`、`file:/run/secrets/key.pem` 和普通文件路径。默认加载器读取本地 PEM，HTTP URL 不是远程拉取密钥的选项。未加密 PKCS#8 私钥使用 `-----BEGIN PRIVATE KEY-----`，X.509 SubjectPublicKeyInfo 公钥使用 `-----BEGIN PUBLIC KEY-----`，不能用证书 PEM 代替这种公钥格式。

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 算法 | 密钥要求 |
| --- | --- |
| `RS256`、`RS384`、`RS512` | RSA 密钥对 |
| `PS256`、`PS384`、`PS512` | RSA 密钥对，RSA-PSS 签名 |
| `ES256` | EC P-256 |
| `ES384` | EC P-384 |
| `ES512` | EC P-521 |

</div>

KeyManager 校验密钥类型、EC 曲线、唯一且非空白的 ID，以及公私钥匹配；活动 key 必须含私钥。JWT access token 通常使用活动 key，ID Token 使用客户端的 [id-token-signature-algorithm](./clients#token-settings)。若该算法与活动 key 不同，必须恰好有一个对应算法的签名私钥；非活动算法存在多个私钥会产生歧义并被拒绝。

OIDC 还要求可用密钥集中存在 RS256 签名私钥，即使某个客户端选择其他 ID Token 算法也一样。仅有用于验签的 RS256 公钥不满足要求。源码：[OidcProviderConfigurationEndpointHandler][oidc]。

## 应用提供密钥 {#custom-source}

CDI `AuthorizationServerKeySource` 完整替换默认来源，此时不再由默认来源加载 `signing.*`。通过 `KeySet` 返回 JCA 密钥材料，KeyManager 仍执行校验。接口不实现远程签名，也不承诺反复调用 `load()` 实现热更新。

[多 issuer](./configuration#multiple-issuers) 要求每个 `AuthorizationServerTenant` 提供自己的 key source，禁止全局签名配置。每个 tenant 都要满足相同的密钥校验规则。

[config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/AuthorizationServerRuntimeConfig.java
[source]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/token/ConfiguredAuthorizationServerKeySource.java
[manager]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/token/AuthorizationServerKeyManager.java
[oidc]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/oidc/web/OidcProviderConfigurationEndpointHandler.java
