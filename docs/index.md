---
layout: home
title: Quarkus Authorization Server
titleTemplate: Quarkus Authorization Server
description: Add OAuth 2.0 authorization to a Quarkus application or build a dedicated authorization service. Compare integration options and explore the guides, reference and Playground.
markdownStyles: false
home:
  headline: Authorization,
  emphasis: built for Quarkus.
  lead: For new or existing Quarkus systems that own their users and need to authorize other applications to access their APIs. Build an OAuth 2.0 authorization service with optional OpenID Connect, using CDI and Quarkus Security.
  start: Get started
  startHref: /guide/getting-started
  source: View source
  versionNote: Add to your Quarkus application
  foundation: At home in your Quarkus application
  request: Request
  response: Example response
  copy: Copy request
  copied: Copied
  copyFailed: Could not copy. Please select the request text manually.
  exampleNote: Demo credentials. Start the local example first.
  exampleLink: Client Credentials guide
  exampleHref: /guide/client-credentials
  comparison:
    title: Choose how authorization fits your application.
    lead: Your application stack, deployment model and user-management needs shape the choice.
    dimension: What you need
    labels:
      - Integration
      - Deployment
      - Users & management
      - A good fit when
    readMore: Explore the approach
    products:
      - name: Quarkus Authorization Server
        kind: Quarkus application extension
        featured: true
        details:
          - CDI, HTTP Security, SecurityIdentity and build-time wiring.
          - Embed in a Quarkus application, or build a dedicated authorization service.
          - Your application supplies user authentication and any management UI.
          - You use Quarkus and want to own your user model and authorization logic.
        link: Integration guide
        href: /guide/
      - name: Spring Authorization Server
        kind: Spring Security framework
        details:
          - Spring Security filter chains, beans and application configuration.
          - Integrate into a Spring application, or build a dedicated authorization service.
          - Your application supplies user authentication and any management UI.
          - You use Spring Security and want to build your own authorization service.
        link: Official guide
        href: https://docs.spring.io/spring-security/reference/servlet/oauth2/authorization-server/getting-started.html
      - name: Keycloak
        kind: Identity and access management server
        details:
          - A server built on Quarkus, configured through its console and extended through SPIs.
          - Run a Keycloak service; applications connect through identity protocols.
          - Built-in user and account administration, federation and management consoles.
          - You want ready-made identity management, SSO and centralized administration.
        link: Official overview
        href: https://www.keycloak.org/
    note: Compare integration models and responsibilities here. For this extension’s supported protocols and limits, see the guides.
  pathsTitle: From your first token to your application.
  pathsLead: Learn the setup, look up the details, then explore the flow.
  paths:
    - title: Documentation
      subtitle: Learn the essentials
      description: Start the server, get a token, and learn how authorization fits into your application.
      action: Read the guides
      href: /guide/
    - title: Reference
      subtitle: Find the details
      description: Look up configuration, defaults and extension points. The full configuration and architecture handbooks live in the repository.
      action: Open the reference
      href: /reference/
    - title: Playground
      subtitle: Explore the flow
      badge: Live demo
      description: Try four OAuth flows, inspect tokens and call protected APIs. PKCE, JWT and request tools are also available offline.
      action: Open the Playground
      href: /playground/
  architecture: Curious about the path of an authorization request?
  architectureHref: /guide/architecture
  architectureLink: Read the architecture
---
