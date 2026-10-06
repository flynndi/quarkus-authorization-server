---
layout: home
title: OAuth Server Extension for Quarkus (Experimental)
titleTemplate: false
description: 社区维护的实验性 Quarkus 扩展，用于构建 OAuth 2.0 授权服务器，按需启用 OpenID Connect。
markdownStyles: false
home:
  status: 实验性 · 社区维护
  headline: 使用 Quarkus
  emphasis: 构建自己的授权服务。
  lead: 面向有经验、选择自行构建并维护授权服务的团队。为新建或已有系统提供 OAuth 2.0 授权服务器扩展，按需启用 OpenID Connect。
  ownership: 由社区贡献者维护，不由 Quarkus 项目或团队提供和维护。
  start: 快速开始
  startHref: /zh/guide/getting-started
  source: 查看源码
  versionNote: 实验性 Quarkus 扩展
  foundation: 使用 Quarkus 构建协议端点
  request: 请求
  response: 响应示意
  copy: 复制请求
  copied: 已复制
  copyFailed: 复制失败，请手动选择请求文本。
  exampleNote: 使用演示凭据，需先启动本地示例。
  exampleLink: Client Credentials 指南
  exampleHref: /zh/guide/client-credentials
  scope:
    title: 面向选择自行构建并维护授权服务的团队。
    lead: 本项目用于有明确需求的授权服务器开发。应用如果只需要登录或 API 保护，应先考虑成熟的 OAuth/OIDC Provider 与 Quarkus Security。
    items:
      - title: 适用场景
        detail: 新建或已有系统自行管理用户与认证，需要向其他应用签发 token，并选择自行承担授权服务的开发与维护。
      - title: 扩展提供什么
        detail: OAuth 协议端点、客户端认证、consent 和 token 签发。按需启用 OpenID Connect，为客户端登录提供 Provider 能力。
      - title: 团队维护什么
        detail: 用户认证、访问策略、持久化存储、密钥与部署。团队需要评估协议行为、审查安全性，并负责服务运行。
    link: 了解角色与职责
    href: /zh/guide/
  pathsTitle: 从第一次请求，到你的应用。
  pathsLead: 了解接入方式，查阅准确行为，再探索授权流程。
  paths:
    - title: Documentation
      subtitle: 学会使用
      description: 从启动服务、获取 token 开始，了解授权服务器如何接入你的应用。
      action: 阅读使用指南
      href: /zh/guide/
    - title: Reference
      subtitle: 查阅细节
      description: 查找配置项、默认值与扩展方式。了解协议边界与支持的定制方式。
      action: 打开参考手册
      href: /zh/reference/
    - title: Playground
      subtitle: 理解流程
      badge: 在线演示
      description: 体验四种真实 OAuth 授权流程，查看 Token 并调用受保护的 API；也可离线使用 PKCE、JWT 和请求工具。
      action: 打开 Playground
      href: /zh/playground/
  architecture: 想了解一次授权请求如何流转？
  architectureHref: /zh/guide/architecture
  architectureLink: 阅读架构说明
---
