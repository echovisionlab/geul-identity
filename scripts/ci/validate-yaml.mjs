#!/usr/bin/env node
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { parseDocument } from "yaml";

const repoRoot = process.cwd();
const ignoredDirectories = new Set([".git", "node_modules"]);
const yamlExtensions = new Set([".yml", ".yaml"]);
const errors = [];

function walk(directoryPath) {
  for (const entry of readdirSync(directoryPath, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) {
        walk(path.join(directoryPath, entry.name));
      }
      continue;
    }

    if (entry.isFile() && yamlExtensions.has(path.extname(entry.name))) {
      validateYamlFile(path.join(directoryPath, entry.name));
    }
  }
}

function validateYamlFile(filePath) {
  const relativePath = path.relative(repoRoot, filePath);
  const document = parseDocument(readFileSync(filePath, "utf8"), {
    prettyErrors: true,
    strict: true,
    uniqueKeys: true,
  });

  for (const error of document.errors) {
    errors.push(`${relativePath}: ${error.message}`);
  }
}

walk(repoRoot);

if (errors.length > 0) {
  console.error(errors.join("\n"));
  process.exit(1);
}
