import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parse } from "yaml";

const composeUrl = new URL("../../compose/identity.yml", import.meta.url);

test("Kratos exports native traces to the central OTLP sanitizer", async () => {
  const compose = parse(await readFile(composeUrl, "utf8"));
  const environment = compose["x-kratos-environment"];

  assert.equal(environment.TRACING_PROVIDER, "otel");
  assert.equal(environment.TRACING_SERVICE_NAME, "geul-kratos");
  assert.equal(
    environment.TRACING_DEPLOYMENT_ENVIRONMENT,
    "${DEPLOYMENT_ENVIRONMENT:-production}",
  );
  assert.equal(
    environment.TRACING_PROVIDERS_OTLP_SERVER_URL,
    "${KRATOS_OTLP_ENDPOINT:?KRATOS_OTLP_ENDPOINT is required}",
  );
  assert.equal(environment.TRACING_PROVIDERS_OTLP_INSECURE, "true");
  assert.equal(
    environment.TRACING_PROVIDERS_OTLP_SAMPLING_SAMPLING_RATIO,
    "${KRATOS_TRACE_SAMPLING_RATIO:-1}",
  );

  for (const serviceName of ["kratos-prod", "kratos-courier-prod"]) {
    assert.strictEqual(
      compose.services[serviceName].environment["<<"],
      environment,
      `${serviceName} must use the shared Kratos environment`,
    );
  }
});
