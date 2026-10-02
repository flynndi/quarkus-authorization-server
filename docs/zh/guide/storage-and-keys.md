# 存储与签名密钥

默认仓储使用内存，未配置签名密钥时使用临时密钥。这方便启动本地应用；持久部署需要明确的存储与密钥方案。

## 通过 CDI 接入 JDBC 仓储

同一个 `quarkus-authorization-server` 扩展包含内存仓储、JDBC 实现、序列化和 SQL 资源，不会自动引入 Agroal 或 JTA。内存仓储无需数据库组件，自定义存储的依赖由应用选择。JDBC 实现接受标准 `javax.sql.DataSource`，由应用按照下文提供仓储 Bean。

使用 Quarkus 托管的数据源时，显式添加 `io.quarkus:quarkus-agroal` 和对应数据库的 Quarkus JDBC driver，例如 `io.quarkus:quarkus-jdbc-postgresql`，并配置数据源：

```properties
quarkus.datasource.db-kind=postgresql
quarkus.datasource.username=authorization_server
quarkus.datasource.password=${AUTHORIZATION_SERVER_DB_PASSWORD}
quarkus.datasource.jdbc.url=jdbc:postgresql://database:5432/authorization_server
```

提供三类仓储接口：

```java
import javax.sql.DataSource;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcJsonCodec;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;

@Singleton
public class AuthorizationStorage {
    @Produces
    @Singleton
    RegisteredClientRepository clients(DataSource dataSource, JdbcJsonCodec jsonCodec) {
        return new JdbcRegisteredClientRepository(dataSource, jsonCodec);
    }

    @Produces
    @Singleton
    OAuth2AuthorizationService authorizations(DataSource dataSource, RegisteredClientRepository clients, JdbcJsonCodec jsonCodec) {
        return new JdbcOAuth2AuthorizationService(dataSource, clients, jsonCodec);
    }

    @Produces
    @Singleton
    OAuth2AuthorizationConsentService consents(DataSource dataSource, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(dataSource, clients);
    }
}
```

这些 Bean 替换默认仓储。客户端由应用通过仓储或初始化逻辑注册，`quarkus.authorization-server.clients.*` 不会自动填充自定义仓储。

扩展不创建或迁移表。请基于以下内置 schema 管理适合目标数据库的迁移：

- `META-INF/quarkus-authorization-server/schema/oauth2-registered-client-schema.sql`
- `META-INF/quarkus-authorization-server/schema/oauth2-authorization-schema.sql`
- `META-INF/quarkus-authorization-server/schema/oauth2-authorization-consent-schema.sql`

代码读取脚本时使用对应 JDBC 实现的 `SCHEMA_LOCATION` 常量。脚本使用独立的 classpath 命名空间，不依赖 Java 包布局，也不通过 HTTP 提供。

示例自行初始化内嵌 H2，启动时建表的辅助代码仅供演示，不是生产迁移服务。上面的 PostgreSQL 配置说明数据源接入方式，不代表已经完成 PostgreSQL 迁移验收。

源码：[`AuthorizationServerPersistence`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/src/main/java/io/quarkiverse/authorization/server/example/authorizationcode/authorizationserver/config/AuthorizationServerPersistence.java)。

## JDBC JSON codec

`JdbcOAuth2AuthorizationService` 和 `JdbcRegisteredClientRepository` 使用 `JdbcJsonCodec` 编解码授权 attributes、token metadata、client settings 和 token settings。SQL 列和事务边界不变；codec 替代原先携带 Java 类型信息的 Jackson 模块及其领域对象、集合反射注册。

codec 使用独立 mapper，显式读写 JSON tree。文档包含表示列用途的 `kind` 和数据 `data`，不增加 `formatVersion`，也不与项目发布版本绑定。例如：

```json
{
  "kind": "token-metadata",
  "data": {
    "invalidated": false,
    "claims": {
      "nbf": { "type": "instant", "value": "2030-01-01T00:00:00Z" }
    },
    "extensions": {}
  }
}
```

已知字段采用 `identity`、`authorizationRequest`、`session`、`tokenFormat` 等稳定名称，由 codec 在持久化边界转换运行时属性 key。身份仅保存用户名、角色和经过校验的 actor claims；读取后重建 Quarkus `SecurityIdentity`，不恢复 credentials、请求属性或 permission checker。

扩展值支持字符串、布尔值、null、标准数值包装类型、`BigInteger`、`BigDecimal`、`Instant`、`Duration`、字符串 key 的 Map、List、Set 和内置协议值类型。需要恢复类型的值使用逻辑 `type/value` 包装，数值载荷使用文本保留精度、小数位数和数值类型。Map 也有明确的包装，因此业务数据中的 `type/value` 字段不会被误识别为编解码标记。集合按不可变接口恢复，不保存原 Java 实现类。已知 settings 字段直接使用布尔值和字符串，缺省配置由领域默认值补齐。

扩展通过 `@Singleton` / `@DefaultBean` 提供默认 codec，并收集应用的 `@Default JdbcJsonValueAdapter<?>` CDI Bean；按上面的示例把注入的 codec 传给两个仓储。纯 Java 场景仍可使用原有构造器获得默认 codec，自定义类型则显式传入 `new JdbcJsonCodec(adapters)`。应用 producer 可以覆盖默认装配，不再提供 `setObjectMapper()` 入口，也不修改应用的全局 Jackson 配置。带 `@Identifier` 等自定义 qualifier 的 Bean 留给应用显式装配，不进入默认 codec。adapter ID 使用 `custom:` 前缀，重复 ID/Java 类型及覆盖内置类型的注册会被拒绝。adapter 只能返回普通 JSON tree，不能返回 Jackson POJO node。未知类型、非法协议字段、重复 JSON key 和过深嵌套都会明确失败。`nbf` 必须恢复为 `Instant`，保留 token 的未生效检查。

codec 在返回编码结果前，使用读取端的同一个私有 mapper 解析最终 JSON，让数字、字符串和字段名长度等 Jackson 限制在持久化前生效；每份写入文档会增加一次 JSON 解析，不调用应用 adapter 的读取逻辑。

codec 不读取原有携带 Java 类型信息的 JSON，接入本次改动时需重建可丢弃的开发数据；扩展不会自动迁移或删除现有记录。四类列的固定样本位于 [`runtime/src/test/resources/jdbc-json`](https://github.com/flynndi/quarkus-authorization-server/tree/main/runtime/src/test/resources/jdbc-json)。

## 理解事务边界

JDBC 仓储是同步 API。扩展在 worker 上执行协议工作，自定义调用方也必须使用允许阻塞的上下文。

应用显式引入 `quarkus-agroal` 后，可使用 Quarkus 管理的连接池与事务集成。只有 Agroal API 存在时，仓储才检测 Agroal 的事务参与状态；直接使用普通 JDBC `DataSource` 不要求 Agroal。

Agroal 连接已加入外部 JTA 事务时，遵循外层事务；否则每次仓储写操作使用独立本地事务。扩展不自动把整个 grant 包进事务，也不承诺并发请求下严格原子单次消费。应用的事务边界必须覆盖真正执行 JDBC 的同步工作，仅包住响应式操作的创建过程不够。

见 [`JdbcTransactionSupport`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/jdbc/JdbcTransactionSupport.java)。

## 配置稳定签名密钥

未配置时，服务器生成临时 RSA key。重启后，旧 key 签发的 token 无法用新的 key set 验证。对外部署的 issuer 应提供持久密钥：

```properties
quarkus.authorization-server.issuer=https://auth.example.com
quarkus.authorization-server.signing.key-id=auth-key-1
quarkus.authorization-server.signing.algorithm=RS256
quarkus.authorization-server.signing.private-key-location=file:/run/secrets/auth-private-key.pem
quarkus.authorization-server.signing.public-key-location=file:/run/secrets/auth-public-key.pem
```

私钥 PEM 为 PKCS#8，公钥 PEM 为 X.509 SubjectPublicKeyInfo；也支持 `classpath:` 和普通文件路径。示例附带的 PEM 是公开测试材料，不能复用于真实 issuer。

计划换钥时，可以同时保留旧验证公钥和新签名密钥：

```properties
quarkus.authorization-server.signing.active-key-id=current
quarkus.authorization-server.signing.keys.previous.public-key-location=file:/run/secrets/previous-public.pem
quarkus.authorization-server.signing.keys.current.private-key-location=file:/run/secrets/current-private.pem
quarkus.authorization-server.signing.keys.current.public-key-location=file:/run/secrets/current-public.pem
```

多密钥配置替代上面的单密钥配置，不能混用。Map key 是 `kid`，这里算法默认 RS256。旧 token 有效期间应保留对应验证 key，并考虑资源端 JWKS 缓存。Key loading 不是热更新 API，应使用目标 key set 重新部署或重启。应用自行加载密钥时，可以通过 CDI `AuthorizationServerKeySource` 替换配置来源。

源码：[`ConfiguredAuthorizationServerKeySource`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/token/ConfiguredAuthorizationServerKeySource.java)。完整属性见[签名密钥](/zh/reference/signing)，tenant 隔离见[多 issuer](/zh/reference/configuration#multiple-issuers)。
