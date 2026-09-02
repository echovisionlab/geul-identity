#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const root = path.resolve(new URL("../..", import.meta.url).pathname);
const suffix = randomUUID().replaceAll("-", "");
const image = `geul-identity-oathkeeper:ci-${suffix}`;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    stdio: "inherit",
    ...options,
  });
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error(`${command} failed with status ${result.status}`);
}

function removeImage() {
  spawnSync("docker", ["image", "rm", "--force", image], {
    cwd: root,
    stdio: "ignore",
  });
}

try {
  removeImage();
  run("docker", [
    "build",
    "--pull",
    "--no-cache",
    "--progress",
    "plain",
    "--rm",
    "--file",
    "Dockerfile.oathkeeper",
    "--tag",
    image,
    ".",
  ]);
  run(process.execPath, ["scripts/ci/auth-boundary-integration.mjs"], {
    env: { ...process.env, TEST_OATHKEEPER_IMAGE: image },
  });
} finally {
  removeImage();
}

const inspected = spawnSync("docker", ["image", "inspect", image], {
  cwd: root,
  stdio: "ignore",
});
if (inspected.status === 0)
  throw new Error(`Oathkeeper test image was not removed: ${image}`);
