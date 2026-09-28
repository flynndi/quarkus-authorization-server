# 参考手册

查阅配置、HTTP 接口和 CDI 集成规则。每节提供定义实际行为的源码入口。

## 配置

| 页面 | 可查阅内容 |
| --- | --- |
| [服务端配置](./configuration) | 构建/运行期阶段、开关、端点路径、issuer 与 tenant 要求 |
| [注册客户端](./clients) | 认证、grant、redirect、scope、`ClientSettings` 与 `TokenSettings` |
| [签名密钥](./signing) | PEM 路径、单/多密钥、活动 key 选择与 CDI 替换 |
| [DPoP](./dpop) | Proof 算法、时间限制与默认 replay store 容量 |

属性使用 `quarkus.authorization-server` 前缀。每节的阶段和源码说明适用于该节所有条目。运行期值在启动时提供，不代表支持热更新。客户端表格区分了配置映射默认值，以及 `RegisteredClient`、`ClientSettings`、`TokenSettings` 推导的默认值。

## 集成与协议行为

| 页面 | 可查阅内容 |
| --- | --- |
| [OAuth 端点](./endpoints) | 认证、authorize/consent、六种 token grant、introspection、revocation、device 与 PAR 请求 |
| [OIDC 与注册](./oidc-and-registration) | UserInfo、logout、受保护/开放注册、接受的 metadata 和错误 |
| [CDI 扩展点](./extensions) | 默认实现、替换/组合规则、用户身份、tenant 和自定义 grant |
| [协议能力与边界](./protocol-support) | 当前 DPoP、refresh、PAR、注册、持久化和 issuer 边界 |

端点与 SPI 源码链接固定到核对的提交。应用装配和 JDBC 配置见下方使用指南。

应用接入可以阅读[架构](/zh/guide/architecture)、[身份与权限](/zh/guide/identity-and-access)或[存储与签名密钥](/zh/guide/storage-and-keys)。第一次使用扩展，请先看[快速开始](/zh/guide/getting-started)。
