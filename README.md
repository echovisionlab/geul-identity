# Geul Identity

Geul Identity contains the Ory Kratos and Oathkeeper authentication boundary,
MCP OAuth facade, generated access rules, and the contract tests that keep them
aligned. It is a public, history-free distribution of the runtime boundary;
deployment manifests and credentials belong to the deployment owner.

## Runtime contract

The following values are deployment-owned and required. There is no built-in
site origin, domain, service URL, OAuth issuer, or mail `from` address.

| Variable                                          | Purpose                                                               |
| ------------------------------------------------- | --------------------------------------------------------------------- |
| `SITE_ORIGIN`                                     | Exact browser-facing HTTPS origin.                                    |
| `MCP_OAUTH_ISSUER_URL`                            | Exact OAuth issuer origin; it must differ from `SITE_ORIGIN`.         |
| `KRATOS_PUBLIC_URL`                               | Exact Kratos public service origin used by Oathkeeper session checks. |
| `KRATOS_ADMIN_URL`                                | Exact Kratos admin service origin.                                    |
| `HYDRA_ADMIN_URL`                                 | Exact Hydra admin service origin used for token introspection.        |
| `AUTHORIZATION_URL`                               | Exact internal authorization service origin.                          |
| `AUTH_HEADER_NAME`                                | The one typed MCP authentication-context header.                      |
| `INTERNAL_SERVICE_HEADER_NAME`                    | The trusted service-to-service header.                                |
| `SESSION_COOKIE_NAME`                             | The shared browser session cookie name.                               |
| `KRATOS_DATABASE_DSN`                             | Kratos SQL connection string.                                         |
| `KRATOS_SECRETS_COOKIE` / `KRATOS_SECRETS_CIPHER` | Kratos secret material.                                               |
| `BACKEND_TOKEN_SIGNING_SECRET`                    | Secret for trusted internal calls.                                    |
| `API_INTERNAL_URL`                                | Internal API origin for Kratos hooks and courier.                     |
| `KRATOS_PASSKEY_RP_ID`                            | WebAuthn relying-party ID selected for the deployment domain.         |
| `KRATOS_OTLP_ENDPOINT`                            | OTLP collector endpoint.                                              |

Google and GitHub OIDC client IDs and secrets are required when those providers
are enabled. `KRATOS_PASSKEY_RP_DISPLAY_NAME` is the only product default and is
`Geul`; code-flow lifespan, trace sampling, local ports, and project names have
non-domain operational defaults.

The three authentication-boundary names above are the only name source for the
typed auth context, Oathkeeper rule generation, and Oathkeeper rendering. The
renderer rejects missing, malformed, colliding, or protocol-reserved names.

## Rendering and placeholders

`config/oathkeeper/oathkeeper.yml` is a template. Its `__KRATOS_PUBLIC_URL__`,
`__HYDRA_ADMIN_URL__`, and `__AUTHORIZATION_URL__` markers, together with the
`.example.invalid` route values in `config/oathkeeper/routes.yml`, are
placeholders and must never be deployed unchanged. Render the runtime config
with the deployment-owned values:

```sh
/usr/local/bin/render-oathkeeper-config \
  --template-directory /etc/oathkeeper-template \
  --output-directory /etc/oathkeeper
```

Rendering is fail-closed: all three boundary names, both origins, and all three
service origins must be present and valid before an output is published.
Route upstream origins remain deployment-owned input to the environment-free
rule generator; replace the route placeholders before publishing `rules.yml`.

## Development checks

```sh
npm ci
go test ./...
npm test
npm run check:oathkeeper-rules
npm run generate:spicedb-schema
npm run check:spicedb:zed
npm run check:compose
npm run test:auth-boundary
npm run test:spicedb
```

The SpiceDB catalog is generated from the checked-in schema, and the runtime
integration exercises that schema with the public
`github.com/echovisionlab/geul-event-contracts` contract. The repository does
not contain migration-only cutover tools or deployment state.

Release images are intended to use these repository candidates:

- `registry.dsub.io/echovisionlab/geul-identity-oathkeeper`
- `registry.dsub.io/echovisionlab/geul-identity-mcp-oauth-facade`

## License

Copyright 2026 Echo Vision Lab. Licensed under the PolyForm Noncommercial
License 1.0.0. See [LICENSE.md](LICENSE.md).

Maintainer: state303 <state303@dsub.io>.
