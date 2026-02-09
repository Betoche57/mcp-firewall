#!/usr/bin/env node

"use strict";

const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const binaryName =
  process.platform === "win32" ? "mcp-firewall.exe" : "mcp-firewall";
const binaryPath = path.join(__dirname, "bin", binaryName);

if (!fs.existsSync(binaryPath)) {
  console.error(
    "mcp-firewall binary not found. Run 'npm install' or 'node install.js' first."
  );
  process.exit(1);
}

try {
  const result = execFileSync(binaryPath, process.argv.slice(2), {
    stdio: "inherit",
  });
  process.exit(0);
} catch (err) {
  if (err.status !== undefined) {
    process.exit(err.status);
  }
  console.error(err.message);
  process.exit(1);
}
