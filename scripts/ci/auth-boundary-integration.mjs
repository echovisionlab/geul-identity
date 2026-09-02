#!/usr/bin/env node

// Minimal local boundary check. Oathkeeper is real; local HTTP servers model
// Kratos, Hydra OAuth introspection, and API/Collab contracts. Everything is
// ephemeral and removed in finally.
import { spawnSync } from "node:child_process";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";

const root = path.resolve(new URL("../..", import.meta.url).pathname);
const image = process.env.TEST_OATHKEEPER_IMAGE?.trim();
if (!image)
  throw new Error(
    "TEST_OATHKEEPER_IMAGE must identify the locally built Geul Oathkeeper image",
  );
function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const authHeaderName = requiredEnvironment("AUTH_HEADER_NAME");
const internalServiceHeaderName = requiredEnvironment(
  "INTERNAL_SERVICE_HEADER_NAME",
);
const sessionCookieName = requiredEnvironment("SESSION_COOKIE_NAME");
const assertion = "auth-boundary-test-token";
const fixtureIssuerOrigin = "https://sso.example";
const fixtureSiteOrigin = "https://site.example";
const fixtureMcpResource = `${fixtureSiteOrigin}/mcp`;
const identities = {
  admin: "00000000-0000-4000-8000-000000000001",
  author: "00000000-0000-4000-8000-000000000002",
  user: "00000000-0000-4000-8000-000000000003",
};
const sessions = {
  admin: "00000000-0000-4000-8000-000000000011",
  author: "00000000-0000-4000-8000-000000000012",
  user: "00000000-0000-4000-8000-000000000013",
  unavailable: "00000000-0000-4000-8000-000000000014",
};
const mcpPrincipal = {
  identityID: "00000000-0000-4000-8000-000000000021",
  memberID: "00000000-0000-4000-8000-000000000022",
  authenticatedContextBase64: Buffer.from(
    "typed-protobuf-context",
    "utf8",
  ).toString("base64url"),
  oauthDelegationIDBase64: Buffer.from(
    "https://client.example/.well-known/oauth-client",
    "utf8",
  ).toString("base64url"),
  delegationNameBase64: Buffer.from(
    "Example Member · Example Client",
    "utf8",
  ).toString("base64url"),
};
const mcpAdmissionPrincipals = {
  author: mcpPrincipal,
  admin: {
    ...mcpPrincipal,
    identityID: identities.admin,
    memberID: "00000000-0000-4000-8000-000000000031",
  },
  user: {
    ...mcpPrincipal,
    identityID: identities.user,
    memberID: "00000000-0000-4000-8000-000000000032",
  },
  unavailable: {
    ...mcpPrincipal,
    identityID: "00000000-0000-4000-8000-000000000033",
    memberID: "00000000-0000-4000-8000-000000000034",
  },
};
const container = `geul-auth-boundary-${process.pid}-${Date.now()}`;
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "geul-auth-boundary-"));
// Linux containers run as Ory's non-root user. mkdtemp creates 0700, which
// Docker Desktop can mask but a native bind mount correctly rejects.
fs.chmodSync(tempDir, 0o755);

function docker(args, options = {}) {
  const {
    ignoreFailure = false,
    includeStderr = false,
    ...spawnOptions
  } = options;
  const result = spawnSync("docker", args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    ...spawnOptions,
  });
  if (result.status !== 0 && !ignoreFailure)
    throw new Error(`docker ${args.join(" ")} failed: ${result.stderr}`);
  const stdout = result.stdout?.trim() ?? "";
  const stderr = result.stderr?.trim() ?? "";
  return includeStderr ? [stdout, stderr].filter(Boolean).join("\n") : stdout;
}

function listen(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "0.0.0.0", () => {
      server.removeListener("error", reject);
      resolve(server);
    });
  });
}

function sessionCookieValue(header) {
  const prefix = `${sessionCookieName}=`;
  return typeof header === "string" && header.startsWith(prefix)
    ? header.slice(prefix.length)
    : undefined;
}

function generatedMCPRules(upstreamPort, gatewayPort) {
  const generated = fs.readFileSync(
    path.join(root, "config/oathkeeper/rules.yml"),
    "utf8",
  );
  const preflightMarker = "\n- id: mcp-preflight\n";
  const mcpMarker = "\n- id: mcp\n";
  const start = generated.indexOf(preflightMarker);
  const mcpStart = generated.indexOf(mcpMarker, start + preflightMarker.length);
  const end = generated.indexOf("\n- id: ", mcpStart + mcpMarker.length);
  if (start < 0 || mcpStart < 0 || end < 0)
    throw new Error("generated rules do not contain bounded MCP rules");

  const sourceOrigin = "url: '<https://site\\.example\\.invalid/mcp>'";
  const sourceResourceMetadata =
    "resource_metadata: 'https://site.example.invalid/.well-known/oauth-protected-resource/mcp'";
  const sourceUpstream = "url: 'http://api.example.invalid:8000'";
  const sourceAdmission =
    "remote: 'http://authorization.example.invalid:8001/internal/mcp/admission/is-author'";
  const sourceAuthHeader = "          '__AUTH_HEADER_NAME__': '";
  const sourceInternalServiceHeader =
    "          '__INTERNAL_SERVICE_HEADER_NAME__': '{{ env \"TOKEN_SIGNING_SECRET\" }}'";
  const rule = generated.slice(start + 1, end);
  if (
    !rule.includes(sourceOrigin) ||
    !rule.includes(sourceResourceMetadata) ||
    !rule.includes(sourceUpstream) ||
    !rule.includes(sourceAdmission) ||
    !rule.includes(sourceAuthHeader) ||
    !rule.includes(sourceInternalServiceHeader)
  )
    throw new Error("generated MCP rules do not use the configured boundary");
  return rule
    .replaceAll(sourceOrigin, "url: '<https://api.test/mcp>'")
    .replace(
      sourceResourceMetadata,
      "resource_metadata: 'https://api.test/.well-known/oauth-protected-resource/mcp'",
    )
    .replaceAll(
      sourceUpstream,
      `url: 'http://host.docker.internal:${upstreamPort}'`,
    )
    .replace(
      sourceAdmission,
      `remote: 'http://host.docker.internal:${gatewayPort}/internal/mcp/admission/is-author'`,
    )
    .replace(sourceAuthHeader, `          '${authHeaderName}': '`)
    .replace(
      sourceInternalServiceHeader,
      `          '${internalServiceHeaderName}': '{{ env "TOKEN_SIGNING_SECRET" }}'`,
    )
    .split("\n");
}

function port(server) {
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("server is not listening");
  return address.port;
}

function request(portNumber, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: portNumber,
        path: options.path ?? "/",
        method: options.method ?? "GET",
        headers: options.headers,
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
            headers: response.headers,
          }),
        );
      },
    );
    req.once("error", reject);
    req.end(options.body);
  });
}

function writeConfig(kratosPort, gatewayPort, hydraPort, upstreamPort) {
  const write = (name, lines) => {
    const filePath = path.join(tempDir, name);
    fs.writeFileSync(filePath, `${lines.join("\n")}\n`);
    // Native Linux bind mounts preserve the runner UID and umask. Ory runs as
    // a distinct non-root UID, so make the read-only fixture explicitly
    // world-readable instead of depending on Docker Desktop ownership mapping.
    fs.chmodSync(filePath, 0o644);
  };
  write("oathkeeper.yml", [
    "version: v26.2.0",
    "log:",
    "  level: error",
    "serve:",
    "  proxy:",
    "    host: 0.0.0.0",
    "    port: 4455",
    "    trust_forwarded_headers: true",
    "  api:",
    "    host: 0.0.0.0",
    "    port: 4456",
    "access_rules:",
    "  matching_strategy: regexp",
    "  repositories:",
    "    - file:///etc/oathkeeper/rules.yml",
    "errors:",
    "  fallback:",
    "    - json",
    "  handlers:",
    "    json:",
    "      enabled: true",
    "      config:",
    "        verbose: false",
    "    www_authenticate:",
    "      enabled: true",
    "authenticators:",
    "  anonymous:",
    "    enabled: true",
    "  cookie_session:",
    "    enabled: true",
    "    config:",
    `      check_session_url: http://host.docker.internal:${kratosPort}/sessions/whoami`,
    "      preserve_path: true",
    "      extra_from: '@this'",
    "      subject_from: 'identity.id'",
    "      only:",
    `        - '${sessionCookieName}'`,
    "  oauth2_introspection:",
    "    enabled: true",
    "    config:",
    `      introspection_url: http://host.docker.internal:${hydraPort}/admin/oauth2/introspect`,
    "      scope_strategy: exact",
    "      required_scope:",
    "        - mcp",
    "      target_audience:",
    `        - ${fixtureMcpResource}`,
    "      trusted_issuers:",
    `        - ${fixtureIssuerOrigin}`,
    "      token_from:",
    "        header: Authorization",
    "authorizers:",
    "  allow:",
    "    enabled: true",
    "  remote_json:",
    "    enabled: true",
    "    config:",
    `      remote: http://host.docker.internal:${gatewayPort}/api.intra.v1.InternalGatewayAuthorizationService/AuthorizeGatewayAccess`,
    "      headers:",
    "        Content-Type: application/json",
    `        '${internalServiceHeaderName}': ${assertion}`,
    "      payload: '{}'",
    "mutators:",
    "  noop:",
    "    enabled: true",
    "  header:",
    "    enabled: true",
    "    config:",
    "      headers:",
    "        Cookie: ''",
    "        Authorization: ''",
    "        X-Session-Id: '{{ print .Extra.id }}'",
  ]);
  write("rules.yml", [
    ...generatedMCPRules(upstreamPort, gatewayPort),
    "",
    "- id: auth-boundary",
    "  version: v26.2.0",
    "  match:",
    "    url: '<https://api.test/private>'",
    "    methods:",
    "      - GET",
    "  authenticators:",
    "    - handler: cookie_session",
    "  authorizer:",
    "    handler: allow",
    "  mutators:",
    "    - handler: header",
    `  upstream:`,
    `    url: 'http://host.docker.internal:${upstreamPort}'`,
    "",
    "- id: auth-boundary-api-resource",
    "  version: v26.2.0",
    "  match:",
    "    url: '<https://api.test/api/rpc/api.manage.v1.TestService/Method>'",
    "    methods:",
    "      - GET",
    "  authenticators:",
    "    - handler: cookie_session",
    "  authorizer:",
    "    handler: allow",
    "  mutators:",
    "    - handler: header",
    `  upstream:`,
    `    url: 'http://host.docker.internal:${upstreamPort}'`,
    "    strip_path: /api/rpc",
    "",
    "- id: auth-boundary-auth-facade",
    "  version: v26.2.0",
    "  match:",
    "    url: '<https://api.test/api/auth/login>'",
    "    methods:",
    "      - GET",
    "  authenticators:",
    "    - handler: anonymous",
    "  authorizer:",
    "    handler: allow",
    "  mutators:",
    "    - handler: noop",
    `  upstream:`,
    `    url: 'http://host.docker.internal:${upstreamPort}'`,
    "    strip_path: /api/auth",
    "",
    "- id: auth-boundary-collab-resource",
    "  version: v26.2.0",
    "  match:",
    "    url: '<https://api.test/collab/resource>'",
    "    methods:",
    "      - GET",
    "  authenticators:",
    "    - handler: cookie_session",
    "  authorizer:",
    "    handler: allow",
    "  mutators:",
    "    - handler: header",
    `  upstream:`,
    `    url: 'http://host.docker.internal:${upstreamPort}'`,
    "    strip_path: /collab",
    "",
    "- id: auth-boundary-authenticated",
    "  version: v26.2.0",
    "  match:",
    "    url: '<https://api.test/authenticated>'",
    "    methods:",
    "      - GET",
    "  authenticators:",
    "    - handler: cookie_session",
    "  authorizer:",
    "    handler: allow",
    "  mutators:",
    "    - handler: header",
    `  upstream:`,
    `    url: 'http://host.docker.internal:${upstreamPort}'`,
    "",
    "- id: auth-boundary-author",
    "  version: v26.2.0",
    "  match:",
    "    url: '<https://api.test/author>'",
    "    methods:",
    "      - GET",
    "  authenticators:",
    "    - handler: cookie_session",
    "  authorizer:",
    "    handler: remote_json",
    "    config:",
    "      payload: |",
    "        {",
    `          \"account_identity_id\": \"{{ print .Subject }}\",`,
    `          \"session_id\": \"{{ print .Extra.id }}\",`,
    `          \"role\": \"AUTHOR\"`,
    "        }",
    "  mutators:",
    "    - handler: header",
    `  upstream:`,
    `    url: 'http://host.docker.internal:${upstreamPort}'`,
    "",
    "- id: auth-boundary-admin",
    "  version: v26.2.0",
    "  match:",
    "    url: '<https://api.test/admin>'",
    "    methods:",
    "      - GET",
    "  authenticators:",
    "    - handler: cookie_session",
    "  authorizer:",
    "    handler: remote_json",
    "    config:",
    "      payload: |",
    "        {",
    `          \"account_identity_id\": \"{{ print .Subject }}\",`,
    `          \"session_id\": \"{{ print .Extra.id }}\",`,
    `          \"role\": \"ADMIN\"`,
    "        }",
    "  mutators:",
    "    - handler: header",
    `  upstream:`,
    `    url: 'http://host.docker.internal:${upstreamPort}'`,
  ]);
}

async function waitForProxy(proxyPort) {
  const deadline = Date.now() + 30_000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const result = await request(proxyPort, {
        path: "/private",
        headers: {
          Host: "api.test",
          "X-Forwarded-Proto": "https",
          Cookie: `${sessionCookieName}=author`,
        },
      });
      if (result.status !== 404 && result.status !== 502) return;
      lastError = new Error(`readiness status ${result.status}`);
    } catch (error) {
      lastError = error;
    }
    await delay(250);
  }
  const state = docker(
    [
      "inspect",
      "--format",
      "{{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}",
      container,
    ],
    { ignoreFailure: true },
  );
  const logs = docker(["logs", "--tail", "100", container], {
    ignoreFailure: true,
    includeStderr: true,
  });
  throw new Error(
    `Oathkeeper proxy did not become ready: ${lastError}; container=${state}; logs=${logs}`,
  );
}

async function main() {
  let whoamiCalls = 0;
  let gatewayCalls = 0;
  let mcpAdmissionCalls = 0;
  let oauthIntrospectionCalls = 0;
  let upstreamCalls = 0;
  const mcpAdmissionIdentityIDs = [];
  let resourceRevoked = false;
  const kratos = await listen((req, res) => {
    if (req.url !== "/sessions/whoami") return res.writeHead(404).end();
    whoamiCalls += 1;
    const cookie = sessionCookieValue(req.headers.cookie);
    const role = Object.prototype.hasOwnProperty.call(sessions, cookie)
      ? cookie
      : undefined;
    if (!role) return res.writeHead(401).end();
    const identityID =
      role === "unavailable" ? identities.user : identities[role];
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        id: role === "unavailable" ? sessions.unavailable : sessions[role],
        active: true,
        identity: { id: identityID },
      }),
    );
  });
  const hydra = await listen((req, res) => {
    if (req.url !== "/admin/oauth2/introspect" || req.method !== "POST")
      return res.writeHead(404).end();
    oauthIntrospectionCalls += 1;
    const forbiddenCallerHeaders = [
      "authorization",
      "cookie",
      "x-session-id",
      "x-legacy-authenticated-identity-id",
      "x-legacy-authenticated-member-id",
      "x-legacy-authenticated-delegation-id-b64",
      "x-legacy-authenticated-delegation-name-b64",
      "x-legacy-authenticated-delegation-method",
      authHeaderName.toLowerCase(),
      internalServiceHeaderName.toLowerCase(),
    ];
    if (
      !req.headers["content-type"]?.startsWith(
        "application/x-www-form-urlencoded",
      ) ||
      forbiddenCallerHeaders.some((name) => req.headers[name] !== undefined)
    ) {
      return res.writeHead(400).end();
    }
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
      const token = form.get("token");
      if (!token || form.has("scope")) return res.writeHead(400).end();
      if (token === "oauth_invalid") {
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify({ active: false }));
      }
      const principalKey = {
        oauth_valid: "author",
        oauth_admin: "admin",
        oauth_user: "user",
        oauth_unavailable: "unavailable",
      }[token];
      const principal = mcpAdmissionPrincipals[principalKey ?? "author"];
      const response = {
        active: true,
        sub: principal.identityID,
        username: "사용자 A",
        aud: [fixtureMcpResource],
        iss: fixtureIssuerOrigin,
        token_type: "Bearer",
        token_use: "access_token",
        scope: "mcp",
        exp: Math.floor(Date.now() / 1000) + 3600,
        ext: {
          authenticated_context_b64: principal.authenticatedContextBase64,
        },
      };
      switch (token) {
        case "oauth_wrong_issuer":
          response.iss = "https://issuer.invalid";
          break;
        case "oauth_wrong_audience":
          response.aud = [`${fixtureSiteOrigin}/not-mcp`];
          break;
        case "oauth_wrong_scope":
          response.scope = "profile";
          break;
        case "oauth_wrong_method":
          response.ext.authenticated_context_b64 = "***";
          break;
        case "oauth_valid":
        case "oauth_admin":
        case "oauth_user":
        case "oauth_unavailable":
          break;
        default:
          response.active = false;
      }
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify(response));
    });
  });
  const gateway = await listen((req, res) => {
    if (
      req.method !== "POST" ||
      req.headers[internalServiceHeaderName.toLowerCase()] !== assertion
    )
      return res.writeHead(404).end();
    if (req.url === "/internal/mcp/admission/is-author") {
      mcpAdmissionCalls += 1;
      const forbiddenHeaders = Object.keys(req.headers).filter(
        (name) =>
          name === "authorization" ||
          name === "cookie" ||
          name === "x-session-id" ||
          name === "x-member-id" ||
          name === "x-identity-id" ||
          name === "x-role" ||
          name === "x-permission" ||
          name.startsWith("x-legacy-authenticated-"),
      );
      if (
        forbiddenHeaders.length !== 0 ||
        req.headers["content-type"] !== "application/json"
      )
        return res.writeHead(400).end();
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      return req.on("end", () => {
        let input;
        try {
          input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          return res.writeHead(400).end();
        }
        if (Object.keys(input).join(",") !== "account_identity_id")
          return res.writeHead(400).end();
        mcpAdmissionIdentityIDs.push(input.account_identity_id);
        const status = new Map([
          [mcpAdmissionPrincipals.author.identityID, 200],
          [mcpAdmissionPrincipals.admin.identityID, 200],
          [mcpAdmissionPrincipals.user.identityID, 403],
          [mcpAdmissionPrincipals.unavailable.identityID, 503],
        ]).get(input.account_identity_id);
        return res.writeHead(status ?? 403).end();
      });
    }
    if (
      req.url !==
      "/api.intra.v1.InternalGatewayAuthorizationService/AuthorizeGatewayAccess"
    )
      return res.writeHead(404).end();
    gatewayCalls += 1;
    if (req.headers.authorization !== undefined)
      return res.writeHead(400).end();
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      let input;
      try {
        input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        return res.writeHead(400).end();
      }
      const keys = Object.keys(input).sort().join(",");
      if (keys !== "account_identity_id,role,session_id")
        return res.writeHead(400).end();
      if (input.session_id === sessions.unavailable)
        return res.writeHead(503).end();
      const role = Object.keys(sessions).find(
        (candidate) => sessions[candidate] === input.session_id,
      );
      if (
        !role ||
        role === "unavailable" ||
        identities[role] !== input.account_identity_id
      )
        return res.writeHead(401).end();
      const allowed =
        input.role === "AUTHOR"
          ? role === "author" || role === "admin"
          : input.role === "ADMIN" && role === "admin";
      return res.writeHead(allowed ? 200 : 403).end();
    });
  });
  const upstream = await listen((req, res) => {
    upstreamCalls += 1;
    if (req.method === "OPTIONS" && req.url === "/mcp") {
      res.writeHead(204, {
        "access-control-allow-origin": fixtureSiteOrigin,
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "authorization, content-type",
      });
      return res.end();
    }
    if (
      (req.url === "/api.manage.v1.TestService/Method" ||
        req.url === "/resource") &&
      resourceRevoked
    )
      return res.writeHead(403).end();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        requestPath: req.url,
        sessionID: req.headers["x-session-id"],
        forwardedCookie: req.headers.cookie,
        forwardedAuthorization: req.headers.authorization,
        internalService: req.headers[internalServiceHeaderName.toLowerCase()],
        authenticatedContextBase64: req.headers[authHeaderName.toLowerCase()],
      }),
    );
  });
  try {
    writeConfig(port(kratos), port(gateway), port(hydra), port(upstream));
    docker([
      "create",
      "--name",
      container,
      "--add-host",
      "host.docker.internal:host-gateway",
      "-p",
      "127.0.0.1::4455",
      "-p",
      "127.0.0.1::4456",
      "-e",
      `TOKEN_SIGNING_SECRET=${assertion}`,
      image,
      "serve",
      "-c",
      "/etc/oathkeeper/oathkeeper.yml",
    ]);
    // ARC uses a Docker daemon isolated from the runner container's /tmp.
    // Stream the fixtures through the Docker client instead of relying on a
    // host bind path that may resolve to an empty directory in the daemon.
    docker(["cp", `${tempDir}/.`, `${container}:/etc/oathkeeper/`]);
    docker(["start", container]);
    const proxyPort = Number(
      docker(["port", container, "4455/tcp"]).match(/:(\d+)$/)?.[1],
    );
    if (!proxyPort)
      throw new Error("unable to determine Oathkeeper proxy port");
    await waitForProxy(proxyPort);
    // Readiness probes are not part of the authorization assertions.
    whoamiCalls = 0;
    mcpAdmissionCalls = 0;
    mcpAdmissionIdentityIDs.length = 0;
    oauthIntrospectionCalls = 0;
    upstreamCalls = 0;
    const preflight = await request(proxyPort, {
      method: "OPTIONS",
      path: "/mcp",
      headers: {
        Host: "api.test",
        "X-Forwarded-Proto": "https",
        Origin: fixtureSiteOrigin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization, content-type",
      },
    });
    if (
      preflight.status !== 204 ||
      preflight.headers["access-control-allow-origin"] !== fixtureSiteOrigin ||
      oauthIntrospectionCalls !== 0 ||
      mcpAdmissionCalls !== 0 ||
      upstreamCalls !== 1
    )
      throw new Error(
        `MCP preflight status/origin/calls = ${preflight.status}/${preflight.headers["access-control-allow-origin"] ?? ""}/${oauthIntrospectionCalls}/${mcpAdmissionCalls}/${upstreamCalls}`,
      );
    oauthIntrospectionCalls = 0;
    mcpAdmissionCalls = 0;
    upstreamCalls = 0;
    const invalidOAuth = await request(proxyPort, {
      method: "POST",
      path: "/mcp",
      headers: {
        Host: "api.test",
        "X-Forwarded-Proto": "https",
        Authorization: "Bearer oauth_invalid",
      },
    });
    if (invalidOAuth.status < 400 || invalidOAuth.status >= 500)
      throw new Error(`invalid MCP OAuth returned ${invalidOAuth.status}`);
    const expectedMCPChallenge =
      'Bearer resource_metadata="https://api.test/.well-known/oauth-protected-resource/mcp", scope="mcp"';
    if (invalidOAuth.headers["www-authenticate"] !== expectedMCPChallenge)
      throw new Error(
        `invalid MCP OAuth challenge ${JSON.stringify(invalidOAuth.headers["www-authenticate"] ?? null)}, want ${JSON.stringify(expectedMCPChallenge)}`,
      );
    if (
      oauthIntrospectionCalls !== 1 ||
      mcpAdmissionCalls !== 0 ||
      upstreamCalls !== 0
    )
      throw new Error("OAuth bearer did not use exactly one Hydra check");

    const rejectedPAT = await request(proxyPort, {
      method: "POST",
      path: "/mcp",
      headers: {
        Host: "api.test",
        "X-Forwarded-Proto": "https",
        Authorization: "Bearer personal_access_token_invalid",
      },
    });
    if (rejectedPAT.status < 400 || rejectedPAT.status >= 500)
      throw new Error(
        `Remote MCP accepted a personal access token: ${rejectedPAT.status}`,
      );
    if (
      oauthIntrospectionCalls !== 2 ||
      mcpAdmissionCalls !== 0 ||
      upstreamCalls !== 0
    )
      throw new Error(
        "personal access token did not fail in the sole OAuth authenticator",
      );

    for (const token of [
      "oauth_wrong_issuer",
      "oauth_wrong_audience",
      "oauth_wrong_scope",
      "oauth_wrong_method",
    ]) {
      const denied = await request(proxyPort, {
        method: "POST",
        path: "/mcp",
        headers: {
          Host: "api.test",
          "X-Forwarded-Proto": "https",
          Authorization: `Bearer ${token}`,
        },
      });
      const expectedDenial =
        token === "oauth_wrong_method"
          ? denied.status === 500
          : denied.status >= 400 && denied.status < 500;
      if (!expectedDenial)
        throw new Error(`${token} returned ${denied.status}, want denial`);
    }
    if (
      oauthIntrospectionCalls !== 6 ||
      mcpAdmissionCalls !== 1 ||
      upstreamCalls !== 0
    )
      throw new Error(
        "OAuth issuer/audience/scope/delegation denial crossed boundaries",
      );
    const oauthMCP = await request(proxyPort, {
      method: "POST",
      path: "/mcp",
      body: '{"jsonrpc":"2.0"}',
      headers: {
        Host: "api.test",
        "X-Forwarded-Proto": "https",
        Authorization: "Bearer oauth_valid",
        Cookie: "caller-cookie=forged",
        "X-Session-Id": "forged-session",
        [authHeaderName]: "forged-context",
        [internalServiceHeaderName]: "forged-internal-secret",
      },
    });
    if (oauthMCP.status !== 200)
      throw new Error(
        `valid MCP OAuth was denied: ${oauthMCP.status} ${oauthMCP.body}`,
      );
    if (
      oauthIntrospectionCalls !== 7 ||
      mcpAdmissionCalls !== 2 ||
      upstreamCalls !== 1
    )
      throw new Error(
        `MCP OAuth/admission/upstream calls = ${oauthIntrospectionCalls}/${mcpAdmissionCalls}/${upstreamCalls}, want 7/2/1`,
      );
    const oauthProjection = JSON.parse(oauthMCP.body);
    for (const [field, expected] of Object.entries({
      authenticatedContextBase64: mcpPrincipal.authenticatedContextBase64,
      internalService: assertion,
    })) {
      if (oauthProjection[field] !== expected)
        throw new Error(
          `OAuth MCP ${field} = ${oauthProjection[field]}, want ${expected}`,
        );
    }
    if (
      ["forwardedAuthorization", "forwardedCookie", "sessionID"].some(
        (field) =>
          Object.prototype.hasOwnProperty.call(oauthProjection, field) &&
          oauthProjection[field] !== "",
      )
    ) {
      throw new Error(
        "MCP upstream received a raw OAuth or browser credential",
      );
    }
    for (const test of [
      {
        name: "admin inheritance",
        token: "oauth_admin",
        expectedStatus: 200,
        expectedIdentity: mcpAdmissionPrincipals.admin.identityID,
        upstreamDelta: 1,
      },
      {
        name: "user denial",
        token: "oauth_user",
        expectedStatus: 403,
        upstreamDelta: 0,
      },
      {
        name: "admission dependency unavailable",
        token: "oauth_unavailable",
        expectedStatus: 500,
        upstreamDelta: 0,
      },
    ]) {
      const beforeOAuth = oauthIntrospectionCalls;
      const beforeAdmission = mcpAdmissionCalls;
      const beforeUpstream = upstreamCalls;
      const response = await request(proxyPort, {
        method: "POST",
        path: "/mcp",
        body: '{"jsonrpc":"2.0"}',
        headers: {
          Host: "api.test",
          "X-Forwarded-Proto": "https",
          Authorization: `Bearer ${test.token}`,
          Cookie: "caller-cookie=forged",
          "X-Session-Id": "forged-session",
          [authHeaderName]: "forged-context",
          "X-Role": "ADMIN",
          "X-Permission": "is_admin",
        },
      });
      const statusMatches =
        test.expectedStatus === 500
          ? response.status >= 500
          : response.status === test.expectedStatus;
      if (!statusMatches)
        throw new Error(
          `${test.name}: expected ${test.expectedStatus}, got ${response.status}`,
        );
      if (
        oauthIntrospectionCalls !== beforeOAuth + 1 ||
        mcpAdmissionCalls !== beforeAdmission + 1 ||
        upstreamCalls !== beforeUpstream + test.upstreamDelta
      )
        throw new Error(`${test.name} crossed or repeated an MCP boundary`);
      if (test.expectedIdentity) {
        const admissionIdentity = mcpAdmissionIdentityIDs[beforeAdmission];
        if (admissionIdentity !== test.expectedIdentity)
          throw new Error(
            `${test.name}: admission identity ${admissionIdentity}, want ${test.expectedIdentity}`,
          );
      }
    }
    const accepted = await request(proxyPort, {
      path: "/authenticated",
      headers: {
        Host: "api.test",
        "X-Forwarded-Proto": "https",
        Cookie: `${sessionCookieName}=author`,
        Authorization: "Bearer forged",
        "X-Session-Id": "forged-session",
      },
    });
    if (accepted.status !== 200)
      throw new Error(`valid cookie was denied: ${accepted.status}`);
    const projected = JSON.parse(accepted.body);
    if (projected.sessionID !== sessions.author)
      throw new Error("Oathkeeper did not replace the spoofed session header");
    if (projected.forwardedCookie)
      throw new Error("Oathkeeper forwarded the raw session cookie upstream");
    if (projected.forwardedAuthorization)
      throw new Error(
        "Oathkeeper forwarded the raw Authorization header upstream",
      );
    const authFacade = await request(proxyPort, {
      path: "/api/auth/login",
      headers: { Host: "api.test", "X-Forwarded-Proto": "https" },
    });
    if (
      authFacade.status !== 200 ||
      JSON.parse(authFacade.body).requestPath !== "/login"
    ) {
      throw new Error(
        `Oathkeeper did not strip the /api/auth prefix: ${authFacade.status} ${authFacade.body}`,
      );
    }
    for (const [pathName, cookie, expected, authorization] of [
      ["/author", "author", 200, "Bearer must-not-reach-remote-authorizer"],
      ["/author", "user", 403, undefined],
      ["/admin", "admin", 200, undefined],
      ["/admin", "author", 403, undefined],
    ]) {
      const response = await request(proxyPort, {
        path: pathName,
        headers: {
          Host: "api.test",
          "X-Forwarded-Proto": "https",
          Cookie: `${sessionCookieName}=${cookie}`,
          ...(authorization === undefined
            ? {}
            : { Authorization: authorization }),
        },
      });
      if (response.status !== expected)
        throw new Error(
          `${pathName} ${cookie}: expected ${expected}, got ${response.status}`,
        );
    }
    const gatewayCallsBeforeUnavailable = gatewayCalls;
    const unavailable = await request(proxyPort, {
      path: "/admin",
      headers: {
        Host: "api.test",
        "X-Forwarded-Proto": "https",
        Cookie: `${sessionCookieName}=unavailable`,
      },
    });
    if (unavailable.status < 500)
      throw new Error(
        `SpiceDB unavailable was treated as authentication denial: ${unavailable.status}`,
      );
    if (gatewayCalls !== gatewayCallsBeforeUnavailable + 1)
      throw new Error(
        `Oathkeeper retried one authorization decision ${gatewayCalls - gatewayCallsBeforeUnavailable} times`,
      );
    const resource = await request(proxyPort, {
      path: "/api/rpc/api.manage.v1.TestService/Method",
      headers: {
        Host: "api.test",
        "X-Forwarded-Proto": "https",
        Cookie: `${sessionCookieName}=author`,
      },
    });
    if (resource.status !== 200)
      throw new Error(
        `API resource was denied before revoke: ${resource.status}`,
      );
    if (
      JSON.parse(resource.body).requestPath !==
      "/api.manage.v1.TestService/Method"
    )
      throw new Error("Oathkeeper did not strip the /api/rpc prefix");
    const collabResource = await request(proxyPort, {
      path: "/collab/resource",
      headers: {
        Host: "api.test",
        "X-Forwarded-Proto": "https",
        Cookie: `${sessionCookieName}=author`,
      },
    });
    if (collabResource.status !== 200)
      throw new Error(
        `Collab resource was denied before revoke: ${collabResource.status}`,
      );
    if (JSON.parse(collabResource.body).requestPath !== "/resource")
      throw new Error("Oathkeeper did not strip the /collab prefix");
    resourceRevoked = true;
    for (const pathName of [
      "/api/rpc/api.manage.v1.TestService/Method",
      "/collab/resource",
    ]) {
      const response = await request(proxyPort, {
        path: pathName,
        headers: {
          Host: "api.test",
          "X-Forwarded-Proto": "https",
          Cookie: `${sessionCookieName}=author`,
        },
      });
      if (response.status !== 403)
        throw new Error(
          `${pathName} was not denied after resource revoke: ${response.status}`,
        );
    }
    const revoked = await request(proxyPort, {
      path: "/authenticated",
      headers: {
        Host: "api.test",
        "X-Forwarded-Proto": "https",
        Cookie: `${sessionCookieName}=revoked`,
      },
    });
    if (revoked.status < 400 || revoked.status >= 500)
      throw new Error(`revoked cookie was not denied: ${revoked.status}`);
    if (
      whoamiCalls !== 11 ||
      gatewayCalls < 5 ||
      mcpAdmissionCalls !== 5 ||
      oauthIntrospectionCalls !== 10 ||
      upstreamCalls !== 10
    )
      throw new Error(
        `unexpected calls whoami=${whoamiCalls} gateway=${gatewayCalls} mcp_admission=${mcpAdmissionCalls} oauth=${oauthIntrospectionCalls} upstream=${upstreamCalls}`,
      );
    console.log(
      `Oathkeeper cookie/OAuth boundaries -> API/Collab final checks passed (whoami=${whoamiCalls}, MCP admission=${mcpAdmissionCalls}, OAuth introspection=${oauthIntrospectionCalls}, gateway=${gatewayCalls}, upstream=${upstreamCalls})`,
    );
  } finally {
    docker(["rm", "-f", container], { stdio: "ignore", ignoreFailure: true });
    await Promise.all([
      new Promise((resolve) => kratos.close(resolve)),
      new Promise((resolve) => hydra.close(resolve)),
      new Promise((resolve) => gateway.close(resolve)),
      new Promise((resolve) => upstream.close(resolve)),
    ]);
  }
}

try {
  await main();
} finally {
  fs.rmSync(tempDir, { recursive: true, force: true });
}
