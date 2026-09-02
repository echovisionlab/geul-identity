import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import Ajv from "ajv";
import addFormats from "ajv-formats";

const schema = JSON.parse(
  await readFile("config/kratos/identity.schema.json", "utf8"),
);
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validateIdentity = ajv.compile(schema);

function emailWithLength(length) {
  const terminalLength = length - (64 + 1 + 63 + 1 + 63 + 1);
  return `${"a".repeat(64)}@${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(terminalLength)}`;
}

function identityWith(email, pendingEmail) {
  return {
    traits: {
      email,
      ...(pendingEmail ? { pending_email: pendingEmail } : {}),
    },
  };
}

test("canonical email accepts 254 characters and rejects 255", () => {
  assert.equal(validateIdentity(identityWith(emailWithLength(254))), true);
  assert.equal(validateIdentity(identityWith(emailWithLength(255))), false);
  assert.match(JSON.stringify(validateIdentity.errors), /maxLength/);
});

test("pending email accepts 254 characters and rejects 255", () => {
  assert.equal(
    validateIdentity(identityWith("member@example.com", emailWithLength(254))),
    true,
  );
  assert.equal(
    validateIdentity(identityWith("member@example.com", emailWithLength(255))),
    false,
  );
  assert.match(JSON.stringify(validateIdentity.errors), /maxLength/);
});
