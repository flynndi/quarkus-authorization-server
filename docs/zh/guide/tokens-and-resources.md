# Token 与资源服务器

授权服务器签发 token，资源服务器验证 access token 并执行自己的访问规则。示例把两者放在同一应用中方便运行；独立部署时也遵循相同的 token 边界。

## 选择 token 表示

| 表示 | 客户端设置 | 资源端验证方式 |
| --- | --- | --- |
| 签名 JWT | `access-token-format=self-contained`（默认） | 使用 issuer 的 JWKS 验签，再校验 claims |
| 不透明 reference token | `access-token-format=reference` | 认证后调用 issuer 的 introspection 端点，检查返回结果 |

ID Token 向客户端描述 OIDC 登录结果。调用资源 API 应发送 **access token**，而不是 ID Token。JWT 解码不等于验签，也不能证明 token 有效。

## 配置 JWT 资源服务器

资源应用添加 `io.quarkus:quarkus-oidc`。下面的配置对应 Client Credentials 示例的 issuer 和 client ID：

```properties
quarkus.oidc.application-type=service
quarkus.oidc.auth-server-url=http://localhost:8080
quarkus.oidc.discovery-enabled=true
quarkus.oidc.token.audience=machine-client
quarkus.oidc.token.allow-jwt-introspection=false
quarkus.oidc.token.allow-opaque-token-introspection=false
```

这套配置要求授权服务器提供 OIDC discovery（`quarkus.authorization-server.oidc.enabled=true`）。对外部署使用公开 HTTPS issuer。资源 API 可以要求一个 scope：

```java
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import io.quarkus.security.PermissionsAllowed;

@Path("/api/messages")
public class MessageResource {
    @GET
    @PermissionsAllowed("message.read")
    public String messages() {
        return "Hello from the protected API";
    }
}
```

这个资源示例除 `quarkus-oidc` 外还使用 Quarkus REST，它不负责定义授权服务器路由。Form 和 Bearer 并存时，按 [Code 指南](./authorization-code#分开浏览器登录和-api-认证)为 `/api/*` 显式选择 Bearer。

默认 JWT audience 是注册客户端的 client ID。资源端填写实际 client ID；也可以有意定制 access-token audience，并同步修改资源端校验。不要为了绕过不匹配而关闭 audience 检查。

源码：[`application.yml`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/client-credentials/src/main/resources/application.yml)、[`MessageResource`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/client-credentials/src/main/java/io/quarkiverse/authorization/server/example/clientcredentials/MessageResource.java)、[`JwtGenerator`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/token/JwtGenerator.java)。

## 添加应用 claim

通过 CDI 提供 `OAuth2TokenCustomizer<JwtEncodingContext>`，无需替换签名或 token 生成逻辑。例如，把主体角色写入用户 access token：

```java
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;

@Singleton
public class TokenClaims {
    @Produces
    @Singleton
    OAuth2TokenCustomizer<JwtEncodingContext> userAccessTokenClaims() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                    && !AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                context.getClaims().claim("groups", context.getPrincipal().getRoles());
            }
        };
    }
}
```

必须检查 token 类型，因为 JWT customizer 也会参与 ID Token 生成。`quarkus-oidc` 可以把 `groups` 读取为角色，之后可用 `@RolesAllowed` 检查。这里复制了主体的全部角色，应用应按 API 需要缩小范围。尤其在 refresh 时，principal 可能来自历史授权快照，见[身份与权限](./identity-and-access#授权后身份发生变化)。

Reference access token 使用 `OAuth2TokenCustomizer<OAuth2TokenClaimsContext>`。多个带默认 qualifier 的 customizer 可以组合，`@Priority` 越大越先执行，同优先级不保证顺序。替换整个 `OAuth2TokenGenerator` 后，应用负责完整生成链。

## 过期、撤销与 DPoP

撤销会更新授权服务器状态。本地验签 JWT 的资源服务器不会每次请求都查询该状态，签名有效不能证明 token 尚未被服务端撤销。应用应根据需要选择短有效期、introspection 或业务策略。上面的 JWT 专用配置会拒绝不透明 token。

DPoP 在已支持流程中由客户端按需使用。DPoP 绑定的 access token 还需要资源端验证 proof，不能作为普通 Bearer token 使用。现有互操作测试覆盖 `quarkus-oidc` 以及附加的 proof/重放检查；见[集成测试源码](https://github.com/flynndi/quarkus-authorization-server/tree/main/integration-tests)。上面的基础配置不会自动启用这套高级装配。
