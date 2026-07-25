#!/usr/bin/env node
"use strict";

// Launcher for the `azula-cli` meta package. Resolves the platform-specific
// binary published as an npm optionalDependency and execs it, passing
// through argv/stdio untouched. This is the file that ships inside the
// published `azula-cli` package at `bin/azula.js` (see ../package.json's
// "bin" field and ../generate.mjs, which copies it in place).
//
// Layout this expects, matching what dist/npm/generate.mjs emits:
//   node_modules/azula-cli/bin/azula.js            (this file)
//   node_modules/@azula-app/cli-<platform>/bin/azula (the real binary)

const { spawnSync } = require("node:child_process");
const path = require("node:path");

// process.platform + process.arch -> the npm platform package carrying the
// matching prebuilt `azula` binary. Keep in sync with:
//   - the release matrix in .github/workflows/release.yml
//   - the TARGETS list in dist/npm/generate.mjs
const PLATFORM_PACKAGES = {
  "darwin-arm64": "@azula-app/cli-darwin-arm64",
  "darwin-x64": "@azula-app/cli-darwin-x64",
  "linux-x64": "@azula-app/cli-linux-x64",
  "linux-arm64": "@azula-app/cli-linux-arm64",
};

function unsupportedPlatformMessage(key) {
  const supported = Object.keys(PLATFORM_PACKAGES).sort().join(", ");
  return [
    `azula: no prebuilt binary for this platform (${key}).`,
    `Supported platforms: ${supported}.`,
    "Build from source instead: `cargo install azula` (requires a Rust toolchain).",
    "https://github.com/Azula-App/azula-cli",
  ].join("\n");
}

function missingPackageMessage(pkgName) {
  return [
    `azula: the platform package "${pkgName}" is not installed.`,
    "This usually means npm skipped an optionalDependency — a lockfile from",
    "a different platform, an offline/cached install, or `--omit=optional`.",
    `Try: npm install ${pkgName}`,
    "Or reinstall clean: npm install azula-cli --force",
  ].join("\n");
}

function resolveBinaryPath() {
  const key = `${process.platform}-${process.arch}`;
  const pkgName = PLATFORM_PACKAGES[key];
  if (!pkgName) {
    return { error: unsupportedPlatformMessage(key) };
  }

  let pkgDir;
  try {
    // require.resolve walks node_modules resolution, so this finds the
    // package whether it landed flat or nested (older npm hoisting).
    pkgDir = path.dirname(require.resolve(`${pkgName}/package.json`));
  } catch {
    return { error: missingPackageMessage(pkgName) };
  }

  const binName = process.platform === "win32" ? "azula.exe" : "azula";
  return { binaryPath: path.join(pkgDir, "bin", binName) };
}

function main() {
  const { binaryPath, error } = resolveBinaryPath();
  if (error) {
    console.error(error);
    process.exitCode = 1;
    return;
  }

  const result = spawnSync(binaryPath, process.argv.slice(2), {
    stdio: "inherit",
  });

  if (result.error) {
    console.error(`azula: failed to launch "${binaryPath}": ${result.error.message}`);
    process.exitCode = 1;
    return;
  }

  if (result.signal) {
    // Mirror the child's termination signal as best node allows.
    process.exitCode = 1;
    return;
  }

  process.exitCode = result.status === null ? 1 : result.status;
}

main();
