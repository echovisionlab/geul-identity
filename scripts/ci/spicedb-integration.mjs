import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

import { v1 } from "@authzed/authzed-node";

const root = path.resolve(new URL("../..", import.meta.url).pathname);
const schemaPath = path.join(root, "config/spicedb/schema.generated.zed");
const relationshipsPath = path.join(
  root,
  "config/spicedb/fixtures/relationships.txt",
);
const parityFixturePath = path.join(
  root,
  "config/spicedb/fixtures/parity.json",
);
const spicedbImage = "authzed/spicedb:v1.56.0";
const token = "geul-spicedb-integration-token";
const name = `geul-spicedb-test-${process.pid}-${Date.now()}`;
const fullyConsistent = v1.Consistency.create({
  requirement: { oneofKind: "fullyConsistent", fullyConsistent: true },
});

let client;
let serverStarted = false;
let cleaned = false;

function runDocker(args) {
  const result = spawnSync("docker", args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    throw new Error(
      `docker ${args.join(" ")} failed with status ${result.status}: ${result.stderr}`,
    );
  }
  return result.stdout?.trim() ?? "";
}

function spicedbEndpoint() {
  const binding = runDocker(["port", name, "50051/tcp"]);
  const hostPort = binding.match(/:(\d+)$/)?.[1];
  if (!hostPort) {
    throw new Error(`SpiceDB did not publish a local gRPC port: ${binding}`);
  }
  return `127.0.0.1:${hostPort}`;
}

function cleanup() {
  if (cleaned) return;
  cleaned = true;
  client?.close();
  if (serverStarted) {
    spawnSync("docker", ["rm", "-f", name], { stdio: "ignore" });
  }
}

function stopForSignal(signal) {
  cleanup();
  process.exit(signal === "SIGINT" ? 130 : 143);
}

process.once("SIGINT", () => stopForSignal("SIGINT"));
process.once("SIGTERM", () => stopForSignal("SIGTERM"));

function splitRequired(value, delimiter, description) {
  const index = value.indexOf(delimiter);
  if (index < 1 || index === value.length - delimiter.length) {
    throw new Error(`invalid relationship fixture ${description}: ${value}`);
  }
  return [value.slice(0, index), value.slice(index + delimiter.length)];
}

function objectReference(value, description) {
  const [objectType, objectId] = splitRequired(value, ":", description);
  return v1.ObjectReference.create({ objectType, objectId });
}

function subjectReference(value) {
  const [object, optionalRelation] = value.includes("#")
    ? splitRequired(value, "#", "subject")
    : [value, ""];
  return v1.SubjectReference.create({
    object: objectReference(object, "subject object"),
    optionalRelation,
  });
}

function relationship(value) {
  const [resourceAndRelation, subject] = splitRequired(value, "@", "tuple");
  const [resource, relation] = splitRequired(
    resourceAndRelation,
    "#",
    "resource relation",
  );
  return v1.Relationship.create({
    resource: objectReference(resource, "resource"),
    relation,
    subject: subjectReference(subject),
  });
}

function tupleFromRelationship(value) {
  const resource = `${value.resource.objectType}:${value.resource.objectId}`;
  const subject = `${value.subject.object.objectType}:${value.subject.object.objectId}${
    value.subject.optionalRelation ? `#${value.subject.optionalRelation}` : ""
  }`;
  return `${resource}#${value.relation}@${subject}`;
}

async function writeRelationship(value, operation) {
  await client.promises.writeRelationships(
    v1.WriteRelationshipsRequest.create({
      updates: [
        v1.RelationshipUpdate.create({
          operation,
          relationship: relationship(value),
        }),
      ],
    }),
  );
}

async function check(resource, permission, subject, expected) {
  const response = await client.promises.checkPermission(
    v1.CheckPermissionRequest.create({
      consistency: fullyConsistent,
      resource: objectReference(resource, "check resource"),
      permission,
      subject: subjectReference(subject),
    }),
  );
  const value =
    response.permissionship ===
    v1.CheckPermissionResponse_Permissionship.HAS_PERMISSION;
  if (value !== expected) {
    throw new Error(
      `${resource} ${permission} ${subject}: expected ${expected}, got ${value}`,
    );
  }
}

async function exportTuples(resourceTypes) {
  const exportedTuples = [];
  for (const resourceType of resourceTypes) {
    const records = await client.promises.readRelationships(
      v1.ReadRelationshipsRequest.create({
        consistency: fullyConsistent,
        relationshipFilter: v1.RelationshipFilter.create({ resourceType }),
      }),
    );
    exportedTuples.push(
      ...records
        .filter((record) => record.relationship)
        .map((record) => tupleFromRelationship(record.relationship)),
    );
  }
  return exportedTuples;
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function writeSchemaWhenReady(schema) {
  let lastError;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      await client.promises.writeSchema(
        v1.WriteSchemaRequest.create({ schema }),
      );
      return;
    } catch (error) {
      lastError = error;
      await sleep(250);
    }
  }
  throw new Error("SpiceDB did not become ready", { cause: lastError });
}

async function main() {
  if (
    !fs.existsSync(schemaPath) ||
    !fs.existsSync(relationshipsPath) ||
    !fs.existsSync(parityFixturePath)
  ) {
    throw new Error("SpiceDB schema or relationship fixture is missing");
  }
  const schema = fs.readFileSync(schemaPath, "utf8");
  const parity = JSON.parse(fs.readFileSync(parityFixturePath, "utf8"));
  if (
    parity.format !== "geul.spicedb.parity.v1" ||
    !Array.isArray(parity.checks)
  ) {
    throw new Error("invalid SpiceDB parity fixture");
  }

  runDocker([
    "run",
    "-d",
    "--rm",
    "--name",
    name,
    "-p",
    "127.0.0.1::50051",
    spicedbImage,
    "serve-testing",
    "--grpc-addr",
    "0.0.0.0:50051",
  ]);
  serverStarted = true;
  client = v1.NewClient(
    token,
    spicedbEndpoint(),
    v1.ClientSecurity.INSECURE_PLAINTEXT_CREDENTIALS,
  );
  await writeSchemaWhenReady(schema);

  const importedTuples = [];
  for (const line of fs.readFileSync(relationshipsPath, "utf8").split("\n")) {
    const value = line.trim();
    if (!value || value.startsWith("#")) continue;
    importedTuples.push(value);
    await writeRelationship(value, v1.RelationshipUpdate_Operation.CREATE);
  }

  const importedResourceTypes = [
    ...new Set(importedTuples.map((value) => value.split(":", 1)[0])),
  ];
  const exportedTuples = await exportTuples(importedResourceTypes);
  if (
    JSON.stringify([...importedTuples].sort()) !==
    JSON.stringify([...exportedTuples].sort())
  ) {
    throw new Error(
      `SpiceDB import/export parity mismatch: imported=${importedTuples.length} exported=${exportedTuples.length}`,
    );
  }

  for (const assertion of parity.checks) {
    await check(
      assertion.resource,
      assertion.permission,
      assertion.subject,
      assertion.allowed,
    );
  }

  const collaborator = "account_identity:00000000-0000-4000-8000-000000000003";
  await writeRelationship(
    `post:post-1#collaborator@${collaborator}`,
    v1.RelationshipUpdate_Operation.DELETE,
  );
  await check(
    parity.after_delete.resource,
    parity.after_delete.permission,
    parity.after_delete.subject,
    parity.after_delete.allowed,
  );
  console.log(
    "SpiceDB v1.56 schema/write/check/delete fully-consistent integration passed",
  );
}

try {
  await main();
} finally {
  cleanup();
}
