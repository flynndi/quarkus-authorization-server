# OAuth Server Extension for Quarkus

**Experimental · Community-maintained**

An experimental, community-maintained Quarkus extension for building OAuth 2.0 authorization servers with optional OpenID Connect support.

Intended for experienced teams that choose to build and maintain their own authorization service for a new or existing system. Applications supply their user authentication, storage and access policies; the extension supplies protocol endpoints and token issuance. The quickstart runs the authorization server and resource API as separate applications.

This project is maintained by its community contributors, not by the Quarkus project or team. Teams adopting it are responsible for evaluating the implementation and operating their authorization service. For applications that simply need login or API protection, start with an established OAuth/OIDC provider and Quarkus Security.

[Documentation, Reference & Playground](https://authorization-server.dev/)

Licensed under the [Apache License 2.0](LICENSE).
