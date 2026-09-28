---
layout: home
title: Quarkus Authorization Server
titleTemplate: Quarkus Authorization Server
description: 在 Quarkus 应用中内嵌 OAuth 2.0 授权能力，或构建独立授权服务。比较接入方式，阅读使用指南、查阅配置参考并体验 Playground。
markdownStyles: false
home:
  headline: 为 Quarkus 应用
  emphasis: 构建授权服务。
  lead: 为 Quarkus 应用提供 OAuth 2.0 授权能力，按需启用 OpenID Connect。可内嵌应用，也可构建独立服务，复用 CDI 与 Quarkus Security。
  start: 快速开始
  startHref: /zh/guide/getting-started
  source: 查看源码
  versionNote: 集成到你的 Quarkus 应用
  foundation: 与你的 Quarkus 应用一起工作
  request: 请求
  response: 响应示意
  copy: 复制请求
  copied: 已复制
  copyFailed: 复制失败，请手动选择请求文本。
  exampleNote: 使用演示凭据，需先启动本地示例。
  exampleLink: Client Credentials 指南
  exampleHref: /zh/guide/client-credentials
  comparison:
    title: 选择适合你的授权服务接入方式。
    lead: 从技术栈、部署方式和用户管理需求出发，找到适合应用的方案。
    dimension: 关注点
    labels:
      - 框架集成
      - 部署方式
      - 用户与管理
      - 适用场景
    readMore: 了解接入方式
    products:
      - name: Quarkus Authorization Server
        kind: Quarkus 原生应用扩展
        featured: true
        details:
          - 复用 CDI、HTTP Security、SecurityIdentity 与构建期装配。
          - 内嵌 Quarkus 应用，或由应用构建独立授权服务。
          - 用户认证和所需的管理界面由应用提供。
          - 已使用 Quarkus，希望自行掌控用户模型与授权逻辑。
        link: 接入指南
        href: /zh/guide/
      - name: Spring Authorization Server
        kind: Spring Security 授权框架
        details:
          - 通过 Spring Security 过滤器链、Bean 和应用配置集成。
          - 集成 Spring 应用，或由应用构建独立授权服务。
          - 用户认证和所需的管理界面由应用提供。
          - 已使用 Spring Security，希望自行构建授权服务。
        link: 官方指南
        href: https://docs.spring.io/spring-security/reference/servlet/oauth2/authorization-server/getting-started.html
      - name: Keycloak
        kind: 身份与访问管理服务
        details:
          - 基于 Quarkus 的服务，通过控制台配置并通过 SPI 扩展。
          - 部署 Keycloak 服务，应用通过身份协议接入。
          - 内置用户与账号管理、用户联合及管理控制台。
          - 需要开箱即用的身份管理、SSO 和集中管理能力。
        link: 官方介绍
        href: https://www.keycloak.org/
    note: 这里比较产品的接入方式与职责划分。本扩展支持的协议和具体边界请参阅使用指南。
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
      description: 查找配置项、默认值与扩展方式。完整配置手册和架构说明在仓库中维护。
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
