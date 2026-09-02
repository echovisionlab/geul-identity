import assert from "node:assert/strict";
import test from "node:test";

import { assertGatewayUsesCanonicalSessionHeader } from "./member-identity-contract.mjs";

test("gateway emits only the canonical session principal", () => {
  const valid = [
    "X-Session-Id: Extra.id regexMatch fail",
    "Cookie: ''",
    "Authorization: ''",
  ].join("\n");
  assert.doesNotThrow(() => assertGatewayUsesCanonicalSessionHeader(valid));
  assert.throws(() =>
    assertGatewayUsesCanonicalSessionHeader(valid.replace("X-Session-Id:", "")),
  );
});
