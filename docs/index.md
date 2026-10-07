---
layout: home
title: OAuth2 and OpenID Connect Server Extension (Experimental)
titleTemplate: false
description: Experimental, community-maintained Quarkus extension for building OAuth 2.0 authorization servers with optional OpenID Connect.
markdownStyles: false
home:
  status: Experimental · Community-maintained
  headline: Build your own
  emphasis: authorization server.
  lead: A Quarkus extension for experienced teams building and maintaining their own OAuth 2.0 authorization service, with optional OpenID Connect. For new or existing systems.
  ownership: Maintained by community contributors, not by the Quarkus project or team.
  start: Get started
  startHref: /guide/getting-started
  source: View source
  versionNote: Experimental extension for Quarkus
  foundation: Protocol endpoints built with Quarkus
  request: Request
  response: Example response
  copy: Copy request
  copied: Copied
  copyFailed: Could not copy. Please select the request text manually.
  exampleNote: Demo credentials. Start the local example first.
  exampleLink: Client Credentials guide
  exampleHref: /guide/client-credentials
  scope:
    title: For teams choosing to build and maintain an authorization service.
    lead: This project is for deliberate authorization-server development. For application login or API protection, start with an established OAuth/OIDC provider and Quarkus Security.
    items:
      - title: Your use case
        detail: You manage users and authentication in a new or existing system, and need to issue tokens to other applications. You choose to own the authorization service and its maintenance.
      - title: What the extension provides
        detail: OAuth protocol endpoints, client authentication, consent and token issuance. Optional OpenID Connect adds provider capabilities for client sign-in.
      - title: What your team maintains
        detail: User authentication, access policies, durable storage, keys and deployment. Your team evaluates protocol behavior, reviews security and operates the service.
    link: Understand the roles and responsibilities
    href: /guide/
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
      description: Look up configuration, defaults and extension points. Check protocol boundaries and supported customization points.
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
