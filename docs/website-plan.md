# 文档网站建设任务与验收清单

状态（2026-09-28）：Documentation / Reference、双语架构图、PG-01 离线工具和 PG-02/03 四种在线授权模式已有实现。文档站正式域名改为 `https://authorization-server.dev`，演示后端继续使用 `https://auth.quarkus-authorization-server.dev`，保留一个通用客户端。前端来源限制、共享回调、canonical、Open Graph URL 和 sitemap 已切换新文档域名；Cloudflare 发布、后端 CORS 生效及正式回调仍需线上复验。

协作方式：按任务 ID 分批实现与 review，执行者自检通过不等于用户 review 已通过。Quarkus 演示后端由用户自行编写与部署，网站侧负责接入。

文档口径（2026-09-23）：项目目前由作者自行测试，待文档完善后首次对外公开。使用指南和 Reference 直接描述当前配置与行为，不引入旧版本兼容、升级迁移或特定提交号的使用门槛；源码依据和真实验证记录保留在对应技术说明中。

目标：在当前仓库的 `/docs` 中建设 **Documentation + Reference + Playground**，使用 VitePress，通过 GitHub 与 Cloudflare 持续发布到 `authorization-server.dev`。

已确认：英文为默认语言（`/`），中文为 `/zh/`；静态前端已由用户部署。用户已提供 HTTPS Quarkus 演示后端。本轮只接入 Authorization Code、Client Credentials、Password、Device Authorization，refresh 作为已签发令牌的后续操作；后端实现不属于网站任务。

## 1. 推荐方案

采用 **VitePress + Cloudflare Workers Static Assets + Workers Builds 的 GitHub 集成**。

- VitePress 负责文档、参考手册和 Vue 交互组件；沿用默认主题，只做品牌色、首页和 Playground 所需的定制。
- 网站代码、依赖清单、构建配置都放在 `docs/`，与 Java 扩展同仓库维护。
- Cloudflare 直接连接 GitHub：`main` 发布正式站点，其他指定分支产生预览；不再用 GitHub Actions 重复部署网站。
- 静态站点不需要自建服务器，也不需要编写 Worker 请求处理代码。真实 OAuth 演示使用单独的 Quarkus 后端。

已采用 Workers Static Assets，前端部署由用户完成。后续沿用这条发布链路，不新建另一套项目。[Cloudflare 官方建议](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/)

| 备选方案 | 判断 |
| --- | --- |
| VitePress + Cloudflare Pages | 可用；若已有 Pages 项目可以继续使用。本项目不同时维护两套部署配置 |
| VitePress + GitHub Pages | 可用，但已有 Cloudflare 域名与托管意向，没有明显收益值得改换发布链路 |
| VitePress 放在现有大陆服务器 | 会增加 Web 服务、证书和发布维护；静态网站暂不使用这条路线，服务器优先留给真实演示后端 |
| 换用 Roq、Docusaurus 等 | 当前没有需求证明需要更换；VitePress 可以直接承载 Markdown 与 Vue Playground，继续使用已选方案 |

VitePress 支持在 Markdown 中使用 Vue 组件，交互代码需要满足静态构建的 SSR 要求。[VitePress Vue 集成](https://vitepress.dev/guide/using-vue)

## 2. 当前基线与范围

规划基于本地源码提交 `4f50dceced5ce172db364aacc07c34c595a9d113`。

当前可复用的内容与代码：

| 来源 | 网站用途 |
| --- | --- |
| [项目 README](../README.md) | 项目定位、依赖坐标、入门入口 |
| [架构指南](guide/architecture.md) | 模块边界、Quarkus 集成、授权流程、已实现能力与限制 |
| [配置参考](reference/configuration.md) | Config、RegisteredClient、CDI、密钥、JDBC、多 issuer |
| [集成测试源码](../integration-tests/) | 高级场景与验证 fixture |
| [Authorization Code 示例](../examples/authorization-code/) | Vue、`oidc-client-ts`、默认登录/consent、资源访问 |
| [双语架构图](diagrams/index.html) | 可交互的运行架构；保留其固定 Git 提交源码依据 |

规划时尚未有 VitePress 工程，集成测试有九个应用。当前目录已调整为 `examples` 四个简单应用和 `integration-tests` 五个高级应用，验收覆盖随场景迁移。

依赖坐标以根目录的 `gradle.properties` 为准；首次公开发布前核实该版本可获取，并验证文档中的安装与示例运行步骤。

**本批网站建设不追加授权服务器协议能力。** DPoP、PAR、动态注册、多 issuer 等已有功能写入 Reference；不因搭网站重新开启功能补齐或架构重构。

## 3. 三个栏目各自解决什么问题

| 栏目 | 读者问题 | 首发内容 | 完成标准 |
| --- | --- | --- | --- |
| Documentation | 如何接入、如何选择、如何运行 | 项目介绍、快速开始、架构、Code/PKCE、Client Credentials、用户身份、token 与资源访问、存储与部署要点 | 新用户引入依赖后能跑通自己的应用，知道需要提供哪些 Bean 和配置 |
| Reference | 某个配置、端点、SPI 的准确行为是什么 | 完整配置索引、默认值/阶段、客户端配置、端点与错误、CDI SPI 与冲突规则、已实现协议边界 | 能查到源码依据，不把未实现能力当作已实现 |
| Playground | 参数怎样组成请求，真实授权结果是什么 | PKCE、JWT、请求构造工具；四种在线授权模式与资源调用 | 按 grant 标记可用性，实际请求/结果有验收证据 |

Documentation 按使用场景组织；Reference 按可查询条目组织，避免维护两份相同配置说明。

### Playground 的交付边界（2026-09-24 修订）

| 能力 | 是否需要后端 | 首发范围 |
| --- | --- | --- |
| S256 PKCE 生成与核验 | 否 | 包含；使用浏览器 Web Crypto，提供可核验样例 |
| JWT header/payload 解码 | 否 | 包含；明确“解码不等于签名验证”，输入留在浏览器 |
| OAuth 请求与 curl 构造 | 否 | 包含；区分导航请求和表单 POST，secret 使用占位符 |
| Code + PKCE → 登录 → consent → callback → token → API | 是 | 使用现有通用客户端 + S256 PKCE，验证登录、consent、固定 callback、token 与两个资源 API；UserInfo / logout 不在本轮范围 |
| Client Credentials、Device、Password、Refresh | 是 | 接入通用 `client_secret_basic` 客户端，refresh 仅在返回 refresh token 后开放 |
| Token Exchange | 是 | 保留离线请求构造器，本轮不新增在线入口 |
| DPoP proof 交互 | 是 | DPoP 不是新的 grant；仅在既有流程需要时单独评估，不因全 grant 后端而自动扩展 |

后端支持全部 grant，不代表所有流程已有网页入口。网站只把完成联调的流程标记为可用；应用私密凭据不进入静态包；按用户要求，现有通用客户端的演示 secret 明确作为公开示例提供，不增加任意目标的通用代理。
静态工具上线是一个可独立交付的阶段，不等于真实 OAuth Playground 已完成。
本轮遵循用户确认的单个通用客户端配置，不拆分 public / confidential client；Code 同时使用 S256 PKCE 和 `client_secret_basic`。用户明确要求公开演示凭据：页面预填通用 client secret 与 `admin / password`，回调后无需重新填写。只将这组演示默认值写入静态产物，用户临时修改的值与 Token 不持久化。

## 4. 目录与发布边界

建议结构如下；这是目标布局，不表示本次已经创建这些文件：

```text
README.md                    # 项目简介与文档网站入口
LICENSE                      # Apache License 2.0
docs/
  package.json / package-lock.json
  .vitepress/
    config.mts
    theme/                    # 主题扩展与按需加载的 Vue 组件
    dist/                     # 生成产物，不提交
  index.md                    # 英文默认首页
  guide/                      # Documentation
  reference/                  # 配置、端点、CDI SPI、能力边界
  playground/                 # 工具页与固定 callback 页面
  zh/                         # 对应中文内容；英文在根目录
  diagrams/                   # 已校验的 Archify 源文件、HTML 与记录
  public/                     # Logo、favicon 等公开静态资源
  scripts/                    # 必要的静态资源准备和链接检查
  website-plan.md             # 内部执行清单，不进入网站导航/搜索/发布
```

- 英文默认使用 `/`，中文使用 `/zh/`；同一篇文章切换语言时跳到对应页面。已发布的 `/en`、`/en/*` 通过 `public/_redirects` 跳到英文根路径，不保留重复页面。核心页双语齐备，其余页面不伪装成已翻译。
- 根目录 README 只保留简介、文档网站与许可证链接。架构、配置、CDI 和协议边界统一在双语站点维护；示例与集成测试模块的 README 暂时删除，后续单独编写。
- 已交付的 `docs/diagrams` HTML 仍保留其固定 Git 提交中的源码路径，不因正文搬家而改写历史证据。
- `docs/diagrams` 保持一个来源；构建时将需要发布的入口、两份图表 HTML 及需要开放下载的 JSON 复制到静态资源目录。截图和检查回执留在仓库，不全部塞入网站。
- VitePress 不会因为某个 HTML 放在 `docs/diagrams` 就自动完整发布它，必须显式处理静态资源复制。生成的副本加入忽略规则。
- 指向 `runtime/`、`deployment/`、`integration-tests/` 的源码链接使用 GitHub 对应版本链接，避免浏览器把 Java 文件或仓库外 Markdown 当作站内路由。
- 网站页面显示适用的扩展版本或 commit；不把历史 native 测试结论解释为当前代码的全量验证。

VitePress 的语言、构建输出和内容排除使用其站点配置；规划文件、生成缓存等通过明确规则排除，不采用全局忽略死链。[VitePress 站点配置](https://vitepress.dev/reference/site-config)

## 5. 任务总表

P0 表示完善当前静态文档站；P1 表示 Playground 与完整验收。前端已部署，不把内容补全误写为部署前置条件。状态由下面对应任务的 checklist 维护，未实测的验收项不勾选。

| ID | 优先级 | 任务与交付物 | 前置任务 |
| --- | --- | --- | --- |
| WEB-01 | P0 | 固定栏目、双语 URL、首发页面与内容来源 | 无 |
| WEB-02 | P0 | VitePress 工程、默认主题、导航、搜索与构建命令 | WEB-01 |
| DOC-01 | P0 | 中英文首页、介绍与可复现快速开始 | WEB-02 |
| DOC-02 | P0 | 中英文核心使用指南与架构说明（已提交 `aadf902`） | DOC-01 |
| REF-01 | P0 | 配置 Reference：字段、默认值、阶段与约束（已提交 `1d1c6d5`） | WEB-02 |
| REF-02 | P0 | 协议端点、CDI SPI 和能力边界 Reference（已提交 `20d5609`） | REF-01 |
| VIS-01 | P1 | 整页双语架构图与文字阅读视图（已实现并检查） | WEB-02 |
| PG-01 | P1 | 浏览器侧 PKCE、JWT 和请求构造工具 | WEB-02、REF-02 |
| DEP-01 | P0 | 已部署；补发布配置记录、自动更新/预览与回退验收 | WEB-02 |
| DEP-02 | P0 | 正式域名、HTTPS、深路径和 404 验收 | DEP-01 |
| PG-02 | P1 | 核对 HTTPS 演示后端与通用客户端契约 | 用户部署后端 |
| PG-03 | P1 | 四种授权模式的网页接入、Code callback 与实际验收 | PG-01、PG-02、DEP-02 |
| QA-01 | P1 | 完整首发验收和维护约定 | 全部上述任务 |

## 6. 逐项 checklist

### WEB-01：信息架构与语言

- [x] 确定 Documentation、Reference、Playground 三个一级导航及首页入口，建立中英文页面对应表。
- [x] 明确核心双语页面：介绍、快速开始、架构、Code/PKCE、Client Credentials、身份与资源访问、配置索引、端点/SPI 索引、Playground 操作与结果提示。
- [x] 标明既有文档的复用、拆分或链接方式；`website-plan.md` 与验收回执不作为面向使用者的正文发布。

验收：能用页面清单回答“新用户从哪开始、参数去哪查、在哪体验”，每页只有一个主要职责。

当前页面对应关系（英文默认）：

| 内容 | 英文 | 中文 |
| --- | --- | --- |
| 首页 | `/` | `/zh/` |
| 介绍 / 快速开始 | `/guide/`、`/guide/getting-started` | `/zh/guide/`、`/zh/guide/getting-started` |
| 架构 | `/guide/architecture` | `/zh/guide/architecture` |
| Code / Client Credentials / 其他 grant | `/guide/authorization-code`、`/guide/client-credentials`、`/guide/other-grants` | 对应 `/zh/guide/...` |
| 身份 / token 与资源端 / 存储密钥 | `/guide/identity-and-access`、`/guide/tokens-and-resources`、`/guide/storage-and-keys` | 对应 `/zh/guide/...` |
| Reference 概览 | `/reference/` | `/zh/reference/` |
| 服务端 / 客户端 / 签名 / DPoP | `/reference/configuration`、`/reference/clients`、`/reference/signing`、`/reference/dpop` | 对应 `/zh/reference/...` |
| OAuth / OIDC 与注册 / CDI / 能力边界 | `/reference/endpoints`、`/reference/oidc-and-registration`、`/reference/extensions`、`/reference/protocol-support` | 对应 `/zh/reference/...` |
| Playground | `/playground/` | `/zh/playground/` |

使用指南按读者场景编写；架构正文、配置字段表、端点、CDI 和协议边界统一在站点维护，不再依赖根目录的独立文档。

### WEB-02：VitePress 基础工程

- [x] 在 `docs/` 建立独立 npm 工程，选择实施时的稳定版 VitePress，锁定依赖和 Node 版本；不引入 Gradle 前端构建插件。
- [x] 提供 `dev`、`build`、`preview` 命令，产物为 `docs/.vitepress/dist`；忽略 `node_modules`、缓存和生成产物。
- [x] 配置双语导航/侧栏、亮暗主题、本地搜索、GitHub 编辑入口、favicon、404、canonical 与 sitemap；预览环境不进入搜索引擎索引。
- [x] Playground 组件按页加载；浏览器 API 在客户端初始化，静态构建不依赖 `window`、用户会话或在线演示后端。

验收：干净检出后 `npm --prefix docs ci`、`npm --prefix docs run build`、`npm --prefix docs run preview` 可运行；普通文档页在后端离线时仍正常打开。

本地搜索优先使用 VitePress 内置能力，不增加搜索服务账号或后端。[VitePress 搜索](https://vitepress.dev/reference/default-theme-search)

### DOC-01：项目入口与快速开始

- [x] 首页说明项目用途、Quarkus 集成方式、主要能力和入口，不放开发过程记录。
- [x] 快速开始以消费扩展为主线：引入依赖、CDI 用户认证、YAML 客户端与登录配置、`quarkus-oidc` 资源端、Authorization Code + client secret 登录兑换及 Bearer API 请求；PKCE 和仓库示例作为后续参考。
- [x] 核实依赖坐标可获取，并从独立工作目录验证依赖接入及完整登录、token、资源请求步骤（2026-09-28 复验见下文）。
- [x] 中英文使用相同命令、配置键和输出含义；示例账号、密钥明确属于演示环境。

验收：从新的工作目录按文档完成启动、获取 token 和一次资源请求，并记录命令、版本与实际结果。

### DOC-02：核心使用指南

- [x] 说明 Authorization Code、Client Credentials 的适用场景和调用链；其他已有 grant 提供简明入口。
- [x] 说明应用用户模型、Quarkus `IdentityProvider`、Form 登录恢复、consent 与 Vue OAuth 客户端的职责；登录/consent 继续使用授权服务器页面。
- [x] 说明 client scope、用户 roles/permissions、token claims 与资源端授权之间的关系，不描述为自动等价或自动继承。
- [x] 提供 token 定制、`quarkus-oidc` 资源访问、JDBC/签名密钥配置的最小示例；核心页面完成英文校对。

验收：示例指向实际类与配置；不要求使用者复制测试 fixture 中整套验收装配，也不重新引入登录/consent JSON 接口。

### REF-01：配置 Reference

- [x] 对照 `AuthorizationServerBuildTimeConfig`、三个 runtime 配置入口及嵌套 `ConfigGroup` 盘点完整属性；分清 build time、build-and-run-time-fixed、runtime。
- [x] 每个条目包含配置键、类型、默认值/是否必填、约束、适用条件、重建要求和源码入口。
- [x] 对照 `ClientSettings`、`TokenSettings` 说明 Builder 与配置映射的对应关系；标明自定义 repository 完整替换默认配置仓储的行为。
- [x] 配置键、默认值与约束在中英文保持一致；先做可审阅表格及源码核对，不为首发新建一套 Java 文档生成框架。

验收：关键默认值有源码依据，尤其 PKCE、consent、可选端点、token TTL/格式、secret 表示与签名密钥。

### REF-02：端点与扩展组件 Reference

- [x] 端点表覆盖实际路径、方法、Content-Type、认证方式、参数、结果和典型错误；标明可选开关与未实现行为。
- [x] CDI 索引覆盖仓储、用户身份、策略/validator/customizer、签名密钥、页面和 tenant 等公开入口，说明默认实现、替换/组合/冲突规则。
- [x] 将 DPoP、PAR、注册、多 issuer、refresh 的现有边界准确列出；不把历史建议升级为开发任务。
- [x] 示例请求与 Reference 一致；先提供手册和 curl，不额外搭建 Swagger UI、管理后台或另一套 API 门户。

验收：以配置类、公开 SPI、端点 handler 和对应测试交叉核对，文档不声称 SAS 全量兼容。

### VIS-01：架构图接入

- [x] 保留 `docs/diagrams` 为源目录，通过构建脚本复制允许发布的文件；不恢复已删除的目录内 Markdown 说明。
- [x] 架构页采用整页图表与文字说明切换，由网站统一语言和主题；设置 iframe 标题，仅进入架构图视图时加载对应语言的图表。
- [x] 验证构建后的静态 URL、语言切换、节点聚焦、固定 commit 源码链接；标明图表的源码基线。

验收：验证的是 VitePress/Cloudflare 下的产物，不仅是原目录的本地 HTTP 预览；首页不提前加载整张图或所有截图。

本轮已检查 VitePress 构建目录及生产预览；Cloudflare 发布后的深路径访问仍归 DEP-01/02 验收。`docs/public/diagrams` 是忽略提交的生成目录，开发和构建加载 VitePress 配置时复制五个允许发布的文件；修改图表源文件后重新启动开发服务或构建。浏览器检查记录见 [index.review.json](diagrams/index.review.json)。

### PG-01：纯浏览器工具

- [x] 用 Vue 组件实现 S256 PKCE、JWT 解码、授权 URL / token 请求构造；提供中英文标签、说明和错误提示。
- [x] PKCE 用已知样例核验，JWT 对无效格式给出明确错误，并区分解码与验签。
- [x] token、verifier 和用户输入不上传分析服务，不放进分享 URL；不保存到长期浏览器存储。
- [x] 请求生成不自动向任意 issuer 发请求，不增加服务端任意 URL 代理；离线请求构造器使用 secret 占位符；在线演示的公开默认凭据见 PG-03。

验收：不启动 Quarkus 后端也能完成全部工具操作，网络检查确认输入不会被额外上传。

### DEP-01：GitHub 与 Cloudflare 构建

- [x] 前端已部署到 Cloudflare（2026-09-19 用户确认；不是本批重新执行的线上验收）。
- [ ] 核对 `main` 自动发布及需要的非生产分支预览。
- [ ] 记录控制台实际生效的根目录、构建/部署命令、Node 和 Wrangler 版本。此前部署指导使用仓库根目录执行 `npm --prefix docs ci && npm --prefix docs run build`，以 CLI `--assets ./docs/.vitepress/dist` 部署；尚无 `wrangler.jsonc`，不为此重复建站。
- [ ] 后续需要固化 Wrangler 配置时，保证控制台与配置文件只有一个有效来源；预览使用非生产版本上传。
- [ ] 设置构建关注路径：文档、站点配置，以及实际引用的源码/示例/版本文件；不能只监听 Markdown 导致代码示例更新后网站不变。
- [ ] 需要 GitHub Actions 时只用于检查，不持有另一条正式部署链路；PR 检查不使用生产后端凭据。

验收：一次分支改动产生可访问预览，合入 `main` 后自动更新正式版本；失败构建不覆盖已有站点，可追溯到 commit 并回退上一版本。

构建、部署和非生产分支命令应按 Workers Builds 分别配置，不能照搬 Pages 的“输出目录”表单。[构建配置](https://developers.cloudflare.com/workers/ci-cd/builds/configuration/) · [关注路径](https://developers.cloudflare.com/workers/ci-cd/builds/build-watch-paths/)

### DEP-02：域名与静态发布

- [ ] 核对 Cloudflare 当前账号、域名 zone 和已有项目，绑定 `authorization-server.dev`；避免覆盖已有业务 DNS 记录。
- [ ] 验证 HTTPS、首页、中英文子路径、静态资源和 404；决定是否使用 `www` 并统一规范 URL。
- [ ] 统一 VitePress `cleanUrls` 与 Cloudflare HTML 路由规则；深路径直接打开/刷新正常，不用全站 SPA fallback 掩盖死链。
- [ ] 从实际访问网络检查可用性；网站部署成功不等于已验证所有地区的访问质量。

验收：首次静态站上线，Documentation 和 Reference 核心双语内容可读、可搜索；后端暂未接入时明确展示真实演示尚不可用。

域名和静态 HTML 路由参考：[Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/) · [HTML handling](https://developers.cloudflare.com/workers/static-assets/routing/advanced/html-handling/)

### PG-02：用户后端的接入契约

网站侧直接调用用户部署的 Kratos，不修改 Java 后端或添加代理。

- [x] HTTPS issuer：`https://auth.quarkus-authorization-server.dev`；discovery 与所有协议端点保持一致。
- [x] 通用 client ID：`quarkus-authorization-server`；认证方式 `client_secret_basic`；Code 使用 S256 PKCE。
- [x] 前端配置的网站 origin：`https://authorization-server.dev`；共享 callback：`https://authorization-server.dev/playground/callback`。英文和中文页面使用同一个 callback，回调后按事务中的语言恢复界面。
- [ ] 部署并确认后端允许新 origin 的 CORS，以及通用客户端注册了上述 callback。2026-09-28 检查时，`kratos/src/main/resources/application.yml` 和 `kratos/src/main/java/com/lx/config/AuthorizationServerPersistence.java` 已包含新值，但线上 token 端点对新 origin 的 OPTIONS 预检仍返回 `403`。后端 issuer、discovery 端点和资源地址保持原域名。
- [x] 本轮申请 `securityIdentity` / `jsonWebToken` scopes，调用 `/api/resource/securityIdentity` / `/api/resource/jsonWebToken`；不扩展 OIDC 登录、UserInfo、logout 或 Token Exchange UI。
- [x] 凭据只使用演示客户端与演示用户。页面预填用户授权公开的演示 secret / 用户名 / 密码；跨域请求不携带 Cookie，浏览器顶层跳转使用后端登录 Cookie。
- [ ] 演示数据重置、流量限制和持续可用性由后端维护者确认，不由网站实现兜底。

### PG-03：四种授权模式的在线接入

- [x] Code：通用客户端 + PKCE，登录与 consent 复用后端页面；共享 callback 校验 state、重复参数、可选响应 issuer 和事务有效期，恢复中英文 UI。
- [x] Callback：临时 verifier / state 放 sessionStorage；回调读取后删除事务并清理 URL，使用预填的演示 secret 兑换；Token 留在内存。
- [x] Client Credentials：Basic 认证并展示 token、请求与资源结果，演示 secret 已按用户要求公开预填，用户修改值不持久化。
- [x] Device：申请设备码、确认链接、轮询；缺省间隔 5 秒，处理 pending、slow_down、超时退避、拒绝、过期和取消。
- [x] Password：只展示既有授权模式，输入演示账号，不将其作为文档站账号系统。
- [x] Refresh：返回 refresh token 时提供操作，保留未轮换的 refresh token，收到新值时替换。
- [x] 共享 Token / Claims / 资源面板；请求日志与资源 JSON 内的原始 Token、凭据脱敏；切换模式或离开页面停止请求。
- [x] 仅在 `https://authorization-server.dev` 启用真实请求；本地、普通预览域名及其他 origin 均不启用。后端仍由独立的固定 issuer 校验约束，CORS 的线上生效情况见 PG-02。
- [ ] 本轮前端发布到 Cloudflare 后，复验真实静态资产与 callback 路由；本地构建 + 真实后端测试不替代正式发布验收。

本轮不做：客户端拆分、资源方法调整、DPoP、Token Exchange 在线入口、UserInfo / logout。协议轮询行为对照 [RFC 8628 §3.5](https://www.rfc-editor.org/rfc/rfc8628.html#section-3.5)。

### QA-01：首发验收与维护

- [ ] 中英文核心页面齐备，导航、语言切换、搜索、代码复制、手机阅读、亮暗主题和键盘操作可用。
- [ ] 构建、链接/锚点检查和浏览器关键流程通过；静态部分不依赖 Java 全量回归，演示后端变更运行对应的 JVM/HTTP 与浏览器验收。
- [ ] 检查部署产物与 URL，未发布内部规划、验收截图全集、私密凭据（公开演示默认值除外）或测试专用管理入口；错误路由确实返回 404。
- [ ] 完成一次 Git 修改 → 预览 → `main` → 自定义域名发布 → 回退演练，并记录实际 commit/URL/结果。
- [ ] 约定后续修改配置、SPI、示例时同步 Reference、核心英文页和相关 Playground；配置自动生成、多版本文档等仅在维护成本证明需要后另开任务。

验收：全部必需项有可复现证据；“静态站已发布”“真实 Playground 已接通”分别记录，不用编译成功代替浏览器和线上验证。

## 7. 执行顺序与停止点

1. **先做 WEB-01 + WEB-02 + DOC-01**：交付可以本地构建、核心导航中英双语、入门可复现的第一版，供 review。
2. **DOC-02（`aadf902`）、REF-01（`1d1c6d5`）及 REF-02（`20d5609`）已提交并 push**。前端已部署，DEP-01/02 保留尚未验证的发布检查。
3. **VIS-01（`c4a580f`）已提交；PG-01 已完成实现与本地检查，用户已授权提交、push**：三个双语工具已接入网站。后续核对 DEP-01/02 的构建与发布设置，线上结果单独验收。
4. **PG-02 + PG-03 四种模式已获提交授权**：后端已接通，具体实现、自检与发布边界见本轮记录。
5. **QA-01 收口**：通过验收后结束本批建设，不继续增加协议能力或管理后台。

## 8. 暂不并入本批的事项

- 不建设用户管理、客户端管理、在线编辑配置、通用 OAuth 调试代理或多租户演示平台。
- 不为首发引入 CMS、远程搜索、独立设计系统、文档多版本镜像或整站自动翻译平台。
- 文档站首批交付未调整集成测试。后续目录整理已单独进行：四个简单应用进入 `examples`，高级场景与既有验收保留在五个 `integration-tests` 应用；这不是文档站上线的前置条件。
- 不因为 Playground 添加新的协议特性。既有 grant 的接入在 PG-03；额外 DPoP 工具、多租户平台等仍须另行评估。

## 9. 给执行 AI 的交接要求

可直接将以下内容作为执行指令：

> 阅读 `docs/website-plan.md` 和当前代码，按选定任务分批实施。英文默认 `/`，中文 `/zh/`，前端已部署到 Cloudflare；网站侧不再承担 Quarkus 演示后端开发，HTTPS 后端已就绪，本轮四种模式接入已获提交、push 授权。后续核对 DEP-01/02 与前端发布后的实际行为。每项任务记录实际检查及边界，完成后交付 review，不自行扩展范围、提交、push 或修改线上部署。

后续批次沿用第 7 节顺序。每批交付时在本节追加一行，必要的截图/日志提供可访问位置，不新建大量过程文档：

| 批次 / 任务 ID | 基线与改动位置 | 检查证据 | 未完成或未验证项 | Review 结论 |
| --- | --- | --- | --- | --- |
| 第一批：WEB-01、WEB-02、DOC-01 | `c923b0d`；示例路径随后在 `a471d47` 更新 | 下方 2026-09-17 本地检查记录 | 干净检出 Quickstart、线上完整验收未记录 | 已按用户要求提交；不等于总验收完成 |
| 第二批：英文默认、分工修正、DOC-02 | 基线 `a471d47`；`docs/.vitepress`、根目录英文 / `docs/zh`、七组新指南 | 下方 2026-09-19 检查记录 | 未提交/未部署本批变更；Cloudflare 旧 URL 重定向、后端联调待验证 | 本地自检通过，待用户 review |

记录要求：

- 基线使用执行前的 Git commit；已提交改动给出 commit 范围，未提交改动列出文件并保留 diff。
- 检查证据至少包含命令、运行环境、退出结果和关键结论；浏览器/部署检查提供 URL、操作与实际结果。无需粘贴全部日志。
- 执行者只勾选实际通过的自检项；依赖域名、后端或账号但尚未完成的检查保持未勾选。Review 结论由 reviewer 填写。
- 对计划的必要偏离先记录原因和影响，不悄悄更换框架、增加授权模式或删除验收模块。

首发整理：删除根目录独立架构/配置文档及示例、集成测试 README；站点链接改为现有指南、Reference 或模块源码。重新初始化 Git 后，固定源码引用与 Archify 审核基线需要在首次提交产生新 hash 后重新核对和生成。

Codex review checklist：

- [ ] 改动与本批任务 ID 一致，未引入未授权范围或覆盖用户改动。
- [ ] 源码、配置、双语内容和文档声称一致；检查项有实际证据，缺少证据的部分标明未验证。
- [ ] 重点复核本批风险：站点路径/SSR、OAuth callback/secret、源码引用、构建与部署配置等实际涉及的部分。
- [ ] 只对改动、失败或缺失证据补充必要验证；不无理由重跑全部 Java/native 测试。
- [ ] 输出问题位置、影响和修复验收条件；区分阻塞问题与可选建议，给出本批通过或待修复结论。

### 总验收 checklist

- [ ] Documentation：核心双语指南能让新用户完成接入。
- [ ] Reference：配置、端点和 CDI 规则有准确源码依据。
- [ ] Playground：纯浏览器工具可用，本轮四种授权模式已与用户后端联调；正式发布后复验 callback 和线上资产。
- [ ] Delivery：GitHub push 可驱动 Cloudflare 更新，自定义域名与回退已验证。
- [ ] Maintenance：代码、文档、英文与演示的更新关系明确，无重复发布链路。

官方资料核对日期：2026-09-17。具体软件版本、Cloudflare 控制台状态和后端环境在相应任务实施时再核实。

### 2026-09-17：首页重写与本地检查

本次重写中英文首页、共享配色与 Reference / Playground 入口文案。首页改为项目介绍、可复制的 Client Credentials 请求和三个栏目入口；移除大 Logo、光晕及重复卡片。当时首页文案在 `docs/index.md` 和 `docs/en/index.md` 的 frontmatter 中维护（2026-09-19 改为英文根目录和 `docs/zh/index.md`），Vue 组件共享布局与复制行为。

架构与配置说明现已集中到网站，原根目录文档及引用已移除。修复目录页 canonical 中的 `$1`、澄清 DPoP 默认支持且客户端可选使用，并补充快速开始切换示例前释放 8080 端口的步骤。

本次检查证据：

- VitePress 1.6.4 生产构建通过；10 个内容页的 canonical 与 sitemap 一致。
- 构建产物中的站内页面与锚点链接检查通过，包含 404 页导航。
- 实际浏览器检查中英文桌面首页、深浅主题、390 px 手机及 768 px 平板断点；所查首页未出现页面横向溢出。
- 实际点击语言切换、复制请求（粘贴核对）、本地搜索及结果跳转、手机菜单和 Reference 导航；查看文档正文与代码块。浏览器检查期间未记录到 console error / warn。
- `git diff --check` 通过。

边界：未重新执行 Java / native 测试、干净检出的完整 Quickstart 或 Cloudflare 部署；Playground 工具及真实在线演示仍未实现。本次检查不代表整批 checklist 验收完成，代码保留待 review。


### 2026-09-19：英文默认、后端分工与 DOC-02

- 英文页面从 `/en/` 移到 `/`，中文从 `/` 移到 `/zh/`；导航、搜索语言、canonical、sitemap、编辑链接和首页入口同步调整。`public/_redirects` 为旧 `/en` 与 `/en/*` 提供 301 规则。
- 新增七组中英文指南：架构、Authorization Code + PKCE、Client Credentials、其他 grant、身份与权限、Token 与资源服务器、存储与签名密钥。源码与示例依据为 `a471d47`，本批不修改 Java 实现。
- 用户确认前端已部署；PG-02 改为接收用户提供的全 grant 后端并核对连接契约，PG-03 按 grant 逐项接入。不再要求网站执行者编写新的 Quarkus 后端。
- `npm --prefix docs run build` 通过；最终修改后 `node docs/node_modules/vitepress/bin/vitepress.js build docs` 再次通过（VitePress 1.6.4 / Node 24.19.0）。
- 产物检查：24 个内容页（另有 404），562 个站内链接及锚点通过；canonical 与 sitemap 一致；27 个不同仓库源码/目录目标存在；双语指南代码块相同。内部计划和旧 `en` 页面目录不进入产物，`_redirects` 已复制到产物。
- 实际浏览器在本地生产预览检查英文默认首页、架构指南及同页语言切换、英文新增内容搜索、深路径/锚点加载、深色代码块、390 px 手机首页与中文正文。所查手机页面没有整体横向溢出；最终页面控制台未记录 error/warn。
- `git diff --check` 通过。

边界：没有提交、push 或改动 Cloudflare 部署。旧 `/en` 跳转规则已静态检查，仍需发布后在 Cloudflare 实测；VitePress 本地 preview 不执行 `_redirects`。未重新运行 Java/native、数据库迁移或干净检出的完整 Quickstart；新增配置片段已对照源码，不把文档构建当作后端运行验收。在线 Playground 等用户提供后端后再联调。REF-01/02、VIS-01、PG-01/02/03 与完整 QA 继续保留未完成状态。


### 2026-09-20：REF-01 配置 Reference

上一批英文默认与 DOC-02 已提交并 push：`aadf902`（`docs: make English default and add core usage guides`）。本批只实施 REF-01，源码核对基线为该提交，未修改 Java 代码。

- 新增四组中英文页面：服务端配置、注册客户端、签名密钥、DPoP；57 个配置属性覆盖四个 ConfigMapping 入口及所有嵌套 ConfigGroup。每节说明前缀、阶段、类型、默认值、条件与源码入口。
- 区分 ConfigMapping 与 Builder 的实际默认值：public Code consent 的推导、client-name 回退内部 id、token TTL 至少 1 秒；说明自定义 RegisteredClientRepository 完整替换默认配置仓储。
- 补齐密钥模式冲突、算法选择、OIDC RS256 私钥要求、多 issuer CDI 条件，以及 DPoP 时钟偏差只允许未来 iat、不延长 proof 到期时间的边界。
- 原配置手册保留集成/协议/CDI/JDBC 说明与已有章节入口；字段表迁到站点，避免维护第二份中文配置表。导航、使用指南链接及执行清单同步更新。
- 生产构建通过（VitePress 1.6.4）；32 个内容页及 404 的站内链接/锚点共 770 个通过，45 个不同仓库目标存在，canonical 与 sitemap 一致。
- 一次性源码盘点检查确认 57 个属性均有中英文表格条目；逐单元格比较技术值，配置示例与显式锚点一致。检查脚本仅用于本次核对，没有引入文档生成框架。
- 实际浏览器验证客户端配置的桌面表格、同页中英文切换与锚点、中文 390 px 手机正文及表格键盘横向滚动、DPoP 属性搜索及结果跳转、深色表格；桌面表格无横向裁切，手机无整页横向溢出。浏览器日志未记录 error/warn。
- `git diff --check` 通过。本批保留未提交，供 review；下一项为 REF-02 端点/CDI/能力边界参考。

边界：本批未重新运行 Java/native、完整 Quickstart 或 Cloudflare 线上验收。前一批 push 的远端 Git 状态已核对，但没有把它当作 Cloudflare 发布成功的证据。Playground 与演示后端接入状态保持不变。

### 2026-09-20：REF-02 端点、CDI 与能力边界

REF-01 已按用户要求提交并 push：`1d1c6d5`（`docs: add bilingual configuration reference`）。本批只实施 REF-02；runtime/deployment 源码核对基线为 `1d1c6d530e0cc7fabf88e7e541316abfcb00abcb`，未改 Java 或协议实现。

新增四组中英文页面：OAuth 端点、OIDC 与注册、CDI 扩展点、协议能力与边界。导航和相关指南已接入，根目录手册改为链接到详细参考，保留应用与 JDBC 接线。79 个源码/测试链接固定到上述提交，并核对该 Git tree 中实际存在的文件。

检查结果：

- VitePress 构建成功，共 40 个内容页；1,090 条站内链接、115 个仓库目标、canonical、sitemap、语言标识和构建排除检查通过。
- 新页面的中英文表格技术值、示例代码、固定源码链接和显式章节锚点一致；既有 57 项配置参考检查仍通过。curl 示例做语法/必填字段核对，未向真实服务器发送请求。
- 本地真实浏览器检查了新增页面、桌面/390px 视口、明暗主题、语言切换保留章节、中英文搜索及结果跳转；页面无整体横向溢出，控制台未见警告/错误。
- 已复核普通 OAuth POST 与 OIDC/PAR 初始 POST、两种注册凭据、UserInfo header transport、public client 限制和 PAR 消费时机；OIDC validator 示例保留默认 HTTPS JWK URL 校验。

边界：本批未提交或 push，供用户 review；未重跑 Java/native、数据库、curl 端到端请求或 Cloudflare 线上验收。未接入用户演示后端；下一项为 VIS-01，不扩大协议任务范围。

### 2026-09-20：VIS-01 整页架构图

REF-02 已按用户要求提交并 push：`20d5609`（`docs: document protocol endpoints and CDI extension points`）。用户 review 后要求将卡片内嵌改为整页图表，并授权检查后提交、push；本批仅覆盖 VIS-01。

- 中英文 Architecture 使用 VitePress `page` 布局，保留网站顶部导航，移除该页的文档侧栏、目录和页脚。进入页面直接显示整页图表；同页提供“架构图 / 文字说明”切换，原 Markdown 正文和章节链接保留。
- 页面直接承载对应语言的 Archify HTML，只有一层 iframe。语言和主题使用网站控制；聚焦节点可写入页面地址并随语言切换保留，文字章节采用相同锚点，站内搜索结果打开对应正文。
- 网站样式只在 iframe 加载时应用：隐藏重复标题、工具栏和已由正文覆盖的摘要卡片，统一外层背景与留白，保留节点详情、来源链接、搜索和缩放。源码基线、JSON 下载和独立查看器/导出入口收进 About。独立查看器仍保留原有功能。
- `docs/diagrams` 保持唯一源目录；VitePress 配置调用复制脚本，开发服务、npm 和直接 CLI 构建使用同一流程。只发布入口 HTML、两份图表 HTML 与两份 JSON，不复制检查截图和回执。
- 保留图表源码基线 `2e538e9f717c8c1798e083a9600661606fae2a0a`：各 11 个组件、31 处源码依据。未修改图表 JSON 或生成的两份 HTML；两份 showcase 校验均为 9/9、无错误或警告，临时 deliver 产物与原文件逐字节一致。
- 生产构建通过；40 个内容页、1,076 条站内链接及锚点、115 个仓库目标、canonical/sitemap、双语配置表 57 项检查通过。五个发布文件在 public、dist 与源目录一致。
- 生产预览浏览器实测：英文整页图在 1440×900、1600×1000、1920×1080、2048×1320 下，页面及 iframe 均无横向/纵向溢出。1440×900 检查了英文浅色和中文深色节点详情；390px 检查了图表和文字模式，页面没有横向溢出，手机图表沿用自身横向浏览和缩放。
- 验证网站主题同步、跨语言保留节点、节点源码链接、图表搜索、正文搜索结果跳转、跨语言章节链接、浏览器回退和 About。网络记录确认首页不请求图表，英文架构页只请求对应英文 HTML，不请求双语包装页、中文版或检查截图。
- 最终生产预览检查未记录新的运行异常。开发检查曾暴露向 VitePress 只读 hash 写值的问题，已改为发出 hashchange 事件并复测。大尺寸截图接口仍有裁切，四种尺寸的 DOM 测量与 1440×900 实际视觉检查分别记录；没有声称本轮重新运行 Archify 自动视觉检查。

边界：本批按用户授权提交、push；未启动 PG-01、未修改 Java 或运行 native、未接入演示后端，也未把 Git push 当作 Cloudflare 发布成功的证据。下一项为 PG-01 浏览器侧 PKCE、JWT 解码和请求构造工具。


### 2026-09-21：PG-01 纯浏览器工具

基线 `4d1dab9`；保留用户已提交的版本元数据和序列化 UID 调整。本批只改 `docs/`，没有新增依赖或修改 Java、Cloudflare 配置。

- 新增 `playground/pkce`、`playground/jwt`、`playground/requests` 及对应中文页面；首页、概览和侧栏标记浏览器工具可用，真实后端仍明确未接通。
- PKCE 使用 Web Crypto 生成 32 字节 verifier 并计算 S256；提供 RFC 7636 Appendix B 样例、手动计算和 challenge 比较。
- JWT 在本地解码 Header/Payload，处理无效编码、JSON、JWE 和输入长度；样例签名为虚构值，输出不表示验签通过，文本通过 Vue 转义展示。
- 请求构造覆盖 Code + PKCE、Client Credentials、Refresh、Device、Password、Token Exchange 的基本参数；支持 `none` / `client_secret_basic` 示例。Code 每次生成新 PKCE、state，含 openid 时生成 nonce。POST 输出为 POSIX curl，凭据/code/token 使用占位符；不自动跳转或发送请求。
- 输入与生成结果仅用组件内存保存，修改输入会清除旧结果；不接入分析上传、URL 状态或浏览器长期存储。共享代码位于 `.vitepress/theme/playground`，协议计算和构造逻辑由 `scripts/oauth-tools.test.mjs` 验证。

检查证据：

- `npm --prefix docs test` 通过；最终修改后 `node --test docs/scripts/*.test.mjs` 再次通过：13 项测试，包括已有的 3 项项目版本测试。覆盖 RFC PKCE 向量、编码错误、Unicode、配套 verifier/redirect、各 grant 参数、Basic client ID 编码和真实 POSIX shell 参数转义；curl 由测试函数替代，没有发网络请求。
- `npm --prefix docs run build` 通过；最终修改后 `node docs/node_modules/vitepress/bin/vitepress.js build docs` 通过（VitePress 1.6.4 / Node 24.19.0）。46 个内容页、1,186 个站内链接/锚点、115 个不同仓库目标通过静态检查，canonical 与 sitemap 一致。
- 实际浏览器使用 `http://localhost:4176/playground/` 的生产预览，验证 PKCE 样例/随机生成/不匹配/非法输入/复制、JWT Unicode 样例/JWE 提示/HTML 转义、六类请求构造与端点错误。英文与中文同页切换、深浅主题、390 px 手机菜单及长输出换行均已检查；复制的 curl 与原输出一致。
- Network 观察：PKCE 与 JWT 的计算操作没有额外请求；请求构造操作只观察到 VitePress 的本地文档资源预取，没有请求配置的授权服务器或上传输入。源码检查未发现工具使用网络请求、分析服务或浏览器存储 API。
- 重建后本地 preview 的旧资源清单曾导致新 JS 文件 404；重启 preview 后复核最终产物，加载失败/运行期异常记录为空，中文错误与 refresh scope 提示可交互。生产预览应在重建后重启。
- `git diff --check` 通过。本批先交付 review，随后按用户授权提交、push；提交前复核变更范围，保留用户的版本配置。

边界：本轮提交、push 不代表 Cloudflare 构建或发布已经完成。没有运行 Java/native、连接 Quarkus 演示后端或执行手动部署。静态工具已可用不等于真实 OAuth 链路验收完成。DEP-01/02 与 PG-02/03 的未验证项继续保留。

### 2026-09-24：PG-02 / PG-03 四种在线授权模式

实现：

- `/playground/` 与 `/zh/playground/` 改为完整页面，复用网站导航、配色和语言切换；四种模式共用 Token、Claims、两个资源 API 和请求记录。
- 单个通用客户端 `quarkus-authorization-server`，所有 Token 请求使用 `client_secret_basic`；保留后端资源方法，不修改 Kratos。
- Code 使用 S256 PKCE，固定 `/playground/callback` 校验并清理参数，然后以同文档导航回到原语言页面。只在内存交接授权码，secret 在回调后重新输入。
- Device 等待首次轮询间隔，尊重 `slow_down`，超时退避，支持取消；刷新令牌只在返回时显示。
- 默认只申请两个资源 scope。本轮没有接入 OIDC 登录 / UserInfo / logout / Token Exchange，也没有新增后端或前端依赖。

检查记录：

- `node --test docs/scripts/*.test.mjs`：24 项通过，其中新增 11 项针对 state / PKCE、可信端点、凭据脱敏、网络错误、取消和 Device 轮询边界。
- VitePress production build 与 `git diff --check` 通过；构建产物包含 callback HTML，callback 不进 sitemap；静态产物中不含当前演示 client secret。
- Chrome 实际请求 HTTPS 后端：Client Credentials / Password / Code + PKCE / Device 均取得 Token；Password refresh 成功；资源未带 Token 返回 401、缺少 scope 返回 403、具有 scope 返回 200。
- Code：实际后端登录、授权回调、Token 兑换，验证中文页面恢复、URL 参数移除、sessionStorage 事务删除。Device：实际设备码页面、确认页面与轮询成功，随后资源返回 200。
- Chrome 本地模拟异常：后端离线提示、state 不匹配时不调用 Token 端点、授权拒绝回调恢复中文；直接 localhost 预览禁止真实后端请求，普通页面加载不自动调用后端。
- 1440px 英文桌面、390px 中文手机、暗色桌面已截图检查，页面无横向溢出；真实流程中未捕获页面 JavaScript 异常。

浏览器验证边界：测试浏览器在注册的文档站 origin 加载本地构建产物，后端请求直接发往真实 HTTPS 服务，不模拟成功响应。正式网站尚未包含新版 callback，授权服务器返回的原始回调 URL 在测试浏览器中重新导航到本地构建，再由前端校验和兑换。这验证了前后端交互，但不等于 Cloudflare 已发布新版资产或回调路由。以上检查在本地实现阶段完成。本轮按用户授权提交并 push，未手动部署前端、未修改后端、未运行 Java / native 测试；Git push 不作为 Cloudflare 发布完成的证据。

### 2026-09-24：公开演示凭据预填

用户要求演示账号、密码及客户端凭据全部预填，继续使用一个通用客户端。

- 固定演示值：client ID `quarkus-authorization-server`，client secret `quarkus-authorization-server-password`，用户名 `admin`，密码 `password`；与 Kratos 注册和初始化数据一致。
- Code / Device 显示登录账号提示；Password 输入框和所有模式的 client secret 默认填好。Code 回调后恢复同一演示 secret，只需点击兑换。
- Reset 恢复演示默认值；用户修改的值不写入 sessionStorage，授权跳转后恢复公开默认值。Token 与脱敏日志策略保持不变。
- 先登录后使用 secret 是两个独立的协议阶段：Authorization Endpoint 认证用户并返回 code；Token Endpoint 验证客户端、code 和 PKCE 后签发 Token。此前手填 secret 是演示 UI 的选择，不是协议要求。
- 本条调整明确替代上述初版“演示 secret 不进入静态包”的限制；仅公开这一组演示值。此次调整已获用户提交、push 授权；Cloudflare 发布结果另行核对。

本次预填调整检查：24 项 Node 测试、VitePress build、diff 检查通过；浏览器未手填凭据即完成真实 Client Credentials / Password 取令牌。另验证 Reset 恢复默认值、Device 登录提示、模拟回调恢复演示 secret 与中文页面、请求日志仍脱敏，390px 手机布局无横向溢出；未捕获页面 JavaScript 异常。本次未重跑真实 Code / Device 全链路，沿用上一批协议检查。


### 2026-09-28：消费扩展的快速开始（DOC-01 复验）

中英文快速开始改为在自己的 Quarkus 应用中引入依赖、配置 CDI 用户认证和 YAML、通过 Authorization Code 登录、使用 client secret 兑换 token，再用 `quarkus-oidc` 保护资源接口。快速开始采用 confidential client 和 `client_secret_basic`，不要求 PKCE；PKCE 留在进阶 Vue 指南。两种语言共用 `docs/snippets/getting-started/` 中的 Java、YAML、HTML 和 shell 片段；仓库示例保留为进阶入口。README、介绍及 grant 指南同步更新入口。

实际验证：

- 在仓库外新建 `authorization-quickstart`，使用 JDK 21、Maven 3.9.11、Quarkus 3.33.3.1，引入 Maven Central 的 `io.github.flynndi:quarkus-authorization-server:1.0.0-beta1`。扩展 runtime/deployment 使用发布包，没有用本地源码替换；其他依赖复用本机缓存。
- 使用文档中的用户 Bean、资源类、YAML 和回调页启动；Chrome 验证默认登录、勾选 `message.read` 后同意授权；执行文档中的 shell 片段完成 state 校验和 HTTP Basic 客户端认证兑换，不发送 PKCE 参数。
- `/api/messages` 携带 access token 返回 `200`，正文包含 `subject=alice` 和 `message=Hello, OAuth!`；只带 Form Cookie 返回 `401`；错误 client secret 返回 `401 / invalid_client`；state 不匹配时 shell 停止兑换；再次兑换同一授权码返回 `400 / invalid_grant`。
- `./gradlew spotlessCheck --no-parallel --max-workers=2`、随后运行的 `:runtime:spotlessCheck :runtime:test` 均通过，runtime 测试 583 项。生产 Java 文件已逐一去除注释后比较，未改变执行代码。
- `npm --prefix docs run build` 通过；Chrome 检查中英文代码片段和版本占位符均正确展开，桌面与手机宽度无页面横向溢出或脚本错误。

验证使用 Maven 3.9.11 执行文档中的 `mvn quarkus:dev`；网络依赖解析复用本机缓存。本轮未发布到 Cloudflare，不将本地页面检查作为线上部署验收。
