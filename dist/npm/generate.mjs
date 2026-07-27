#!/usr/bin/env node
// dist/npm/generate.mjs
//
// Builds the four per-platform npm packages plus the `azula-cli` meta
// package from a directory of already-built release binaries. Called by
// the `publish-npm` job in .github/workflows/release.yml; not meant to be
// run by end users.
//
// Usage:
//   node dist/npm/generate.mjs --version 0.2.0 --bin-dir ./bin-download --out-dir ./npm-out
//
// --bin-dir must contain one subdirectory per Rust target triple, each
// holding the extracted `azula` binary (this is exactly what the workflow's
// "Download release binaries" step produces from the GitHub Release
// tarballs):
//   bin-download/aarch64-apple-darwin/azula
//   bin-download/x86_64-apple-darwin/azula
//   bin-download/x86_64-unknown-linux-musl/azula
//   bin-download/aarch64-unknown-linux-musl/azula
//
// Output, ready for `npm publish <dir>` on each:
//   npm-out/cli-darwin-arm64/   (package @azula-app/cli-darwin-arm64)
//   npm-out/cli-darwin-x64/     (package @azula-app/cli-darwin-x64)
//   npm-out/cli-linux-x64/      (package @azula-app/cli-linux-x64)
//   npm-out/cli-linux-arm64/    (package @azula-app/cli-linux-arm64)
//   npm-out/azula-cli/          (meta package, launcher in bin/azula.js)

import { mkdir, copyFile, writeFile, chmod, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Rust target triple -> npm platform package descriptor. Keep in sync with:
//   - the build matrix in .github/workflows/release.yml
//   - the PLATFORM_PACKAGES map in bin/azula.js
const TARGETS = [
  { rustTarget: "aarch64-apple-darwin", npmSuffix: "darwin-arm64", os: "darwin", cpu: "arm64" },
  { rustTarget: "x86_64-apple-darwin", npmSuffix: "darwin-x64", os: "darwin", cpu: "x64" },
  { rustTarget: "x86_64-unknown-linux-musl", npmSuffix: "linux-x64", os: "linux", cpu: "x64" },
  { rustTarget: "aarch64-unknown-linux-musl", npmSuffix: "linux-arm64", os: "linux", cpu: "arm64" },
];

const SCOPE = "@azula-app";
const META_NAME = "@azula-app/cli";
// Output directory for the meta package. Kept separate from META_NAME
// because a scoped name would otherwise nest as `<out>/@azula-app/cli`;
// the workflow publishes `npm-out/meta/` by this path, not by package name.
const META_DIR = "meta";

function parseArgs(argv) {
  const args = { binDir: null, outDir: null, version: null };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--version") args.version = argv[++i];
    else if (arg === "--bin-dir") args.binDir = argv[++i];
    else if (arg === "--out-dir") args.outDir = argv[++i];
    else throw new Error(`unknown argument: ${arg}`);
  }
  const missing = Object.entries(args)
    .filter(([, v]) => !v)
    .map(([k]) => k);
  if (missing.length > 0) {
    throw new Error(
      `missing required argument(s): ${missing.join(", ")}\n` +
        "usage: generate.mjs --version <v> --bin-dir <dir> --out-dir <dir>",
    );
  }
  return args;
}

async function readJsonTemplate(name) {
  const raw = await readFile(path.join(__dirname, name), "utf8");
  return JSON.parse(raw);
}

async function buildPlatformPackage({ rustTarget, npmSuffix, os, cpu }, version, binDir, outDir) {
  const pkgName = `${SCOPE}/cli-${npmSuffix}`;
  const srcBinary = path.join(binDir, rustTarget, "azula");
  if (!existsSync(srcBinary)) {
    throw new Error(`missing built binary for ${rustTarget} at ${srcBinary}`);
  }

  const pkgDir = path.join(outDir, `cli-${npmSuffix}`);
  const binOutDir = path.join(pkgDir, "bin");
  await mkdir(binOutDir, { recursive: true });

  const destBinary = path.join(binOutDir, "azula");
  await copyFile(srcBinary, destBinary);
  await chmod(destBinary, 0o755);

  const packageJson = {
    name: pkgName,
    version,
    description: `azula CLI prebuilt binary for ${os}/${cpu} (rust target ${rustTarget})`,
    homepage: "https://azula.app",
    repository: {
      type: "git",
      url: "git+https://github.com/Azula-App/azula-cli.git",
    },
    license: "MIT OR Apache-2.0",
    os: [os],
    cpu: [cpu],
    bin: { azula: "bin/azula" },
    files: ["bin/"],
  };
  await writeFile(path.join(pkgDir, "package.json"), JSON.stringify(packageJson, null, 2) + "\n");

  return { pkgName };
}

async function buildMetaPackage(version, platformPkgNames, outDir) {
  const template = await readJsonTemplate("package.json");

  const pkgDir = path.join(outDir, META_DIR);
  const binOutDir = path.join(pkgDir, "bin");
  await mkdir(binOutDir, { recursive: true });

  const launcherDest = path.join(binOutDir, "azula.js");
  await copyFile(path.join(__dirname, "bin", "azula.js"), launcherDest);
  await chmod(launcherDest, 0o755);

  const optionalDependencies = {};
  // Pin exact versions (not a semver range) so npm always resolves the
  // platform package built from the same tag as the meta package —
  // esbuild's platform-package pattern.
  for (const name of platformPkgNames) optionalDependencies[name] = version;

  const packageJson = { ...template, version, optionalDependencies };
  await writeFile(path.join(pkgDir, "package.json"), JSON.stringify(packageJson, null, 2) + "\n");

  return pkgDir;
}

async function main() {
  const { version, binDir, outDir } = parseArgs(process.argv.slice(2));
  await mkdir(outDir, { recursive: true });

  const platformPkgNames = [];
  for (const target of TARGETS) {
    const { pkgName } = await buildPlatformPackage(target, version, binDir, outDir);
    platformPkgNames.push(pkgName);
  }

  const metaDir = await buildMetaPackage(version, platformPkgNames, outDir);

  console.log(`Generated ${TARGETS.length} platform packages + meta package in ${outDir}`);
  console.log(`Publish the platform packages first, then ${META_NAME} (${metaDir}).`);
}

main().catch((err) => {
  console.error(err.stack || String(err));
  process.exitCode = 1;
});
