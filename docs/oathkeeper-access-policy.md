# Oathkeeper access boundary

This document describes the public policy shape in
`config/oathkeeper/routes.yml` and the generated `rules.yml`. It is a contract
guide, not a deployment manifest. The deployment must provide exact origins,
service URLs, and the three authentication-boundary names before rendering or
starting Oathkeeper.

<!-- manage-inventory: authenticated=117 author=25 admin=243 total=385 -->

| Role          | Count |
| ------------- | ----: |
| Authenticated |   117 |
| Author        |    25 |
| Admin         |   243 |

## Boundary rules

- Browser routes are matched against the deployment's exact `SITE_ORIGIN`.
- Internal RPC routes are admitted only through the deployment-owned internal
  Oathkeeper origin and the explicit method rules generated from
  `geul-event-contracts` access annotations.
- Kratos session authentication reads the deployment's `SESSION_COOKIE_NAME`
  and emits only a validated session ID to protected upstreams.
- The MCP route accepts only a Hydra OAuth access token with exact issuer
  `MCP_OAUTH_ISSUER_URL`, exact `mcp` scope, and audience `${SITE_ORIGIN}/mcp`.
- The MCP OAuth introspection extension contains one typed authenticated
  context. Personal-access-token authenticators, raw bearer forwarding, and
  legacy identity/member header families are not part of this boundary.
- Remote authorization receives the deployment's
  `INTERNAL_SERVICE_HEADER_NAME` and rejects requests that contain the bearer,
  browser-cookie, or session transport headers.

## Configuration ownership

`routes.yml` contains `.example.invalid` values solely as inspectable template
markers for route generation. `oathkeeper.yml` contains explicit
`__KRATOS_PUBLIC_URL__`, `__HYDRA_ADMIN_URL__`, and `__AUTHORIZATION_URL__`
markers. The renderer replaces every marker or fails closed; no site, domain,
issuer, service, or mail sender default is inferred.

The generated policy is reproducible with:

```sh
npm run generate:oathkeeper-rules
npm run check:oathkeeper-rules
```

Only the generated route file should be consumed by the Oathkeeper process.
Deployment is responsible for mounting the rendered configuration and for
ensuring its ingress forwards the intended HTTPS origin headers.
