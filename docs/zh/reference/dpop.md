# DPoP 配置

前缀：`quarkus.authorization-server.dpop`。所有属性均为 **`RUN_TIME`**，启动时提供无需重建，不支持逐请求刷新配置。默认支持 DPoP，客户端在支持的流程中携带有效 proof 时使用，没有 `enabled` 总开关。

映射：[DPoPConfig][config]。校验：[DPoPProofVerifier][verifier] 与 [InMemoryDPoPReplayStore][store]。

## 属性 {#properties}

<div class="reference-table" role="region" aria-label="配置表，可按需横向滚动" tabindex="0">

| 属性 | 类型 / 默认值 | 约束或用途 |
| --- | --- | --- |
| `proof-algorithms` | `Set<SignatureAlgorithm>` · `ES256,RS256` | 非空；支持 RS256/384/512、PS256/384/512、ES256/384/512。同一集合发布到 OAuth/OIDC 算法发现中。 |
| `proof-max-age` | `Duration` · `1M` | 必须为正数；proof 在 `iat + proof-max-age` 到期，时钟偏差不会延长此期限。 |
| `clock-skew` | `Duration` · `5S` | 不能为负数，允许 `iat` 超前当前时间的最大容差。 |
| `max-proof-length` | int · `16384` | 必须为正数；compact proof 字符串的最大长度，在解析 JWT 之前检查。 |
| `replay-cache-size` | int · `100000` | 必须为正数；默认内存 replay store 的最大条目数，不配置自定义 store。 |

</div>

默认值对应以下配置片段：

```properties
quarkus.authorization-server.dpop.proof-algorithms=ES256,RS256
quarkus.authorization-server.dpop.proof-max-age=1M
quarkus.authorization-server.dpop.clock-skew=5S
quarkus.authorization-server.dpop.max-proof-length=16384
quarkus.authorization-server.dpop.replay-cache-size=100000
```

Proof 算法与授权服务器的 [token 签名密钥](./signing)独立。例如 ES256 proof 可以绑定 RS256 签名的 access token；此允许列表控制 proof 验证，不决定 token 签名算法。

## Replay store 与适用边界 {#replay-store}

默认 replay store 有容量上限，仅在单 JVM 内去重。使用时清理过期条目，容量已满则拒绝 claim，不驱逐仍有效的条目来接纳新 proof。应用需要其他存储策略时，通过 CDI `DPoPReplayStore` 替换。调大容量不会提供跨实例重放防护。

Authorization Code、Refresh Token、Client Credentials、Device Code、Token Exchange 接受 DPoP proof；Password 请求携带 DPoP header 会被拒绝。Token Exchange 绑定**输出** token，不增加输入 token 绑定的校验或继承。UserInfo 接受携带资源访问 proof 的 DPoP token。本页配置不会配置独立资源服务器的 DPoP 校验。

当前没有服务端 nonce、内建共享 replay 后端或强制 DPoP 的配置。Public client 的刷新限制是另一项规则：public Authorization Code client 不使用 DPoP 也可以得到 Bearer access token，但获取和使用 refresh token 需要受支持的 DPoP 绑定流程。见 [Token 与资源服务器](/zh/guide/tokens-and-resources)。

[config]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/AuthorizationServerRuntimeConfig.java
[verifier]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/dpop/DPoPProofVerifier.java
[store]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/dpop/InMemoryDPoPReplayStore.java
