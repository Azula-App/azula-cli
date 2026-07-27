# dist/ — distribution scaffolding

Everything under here supports `.github/workflows/release.yml`, which builds
and publishes `azula` to crates.io, npm, and Homebrew off a single `v*` tag.
See `openspec/changes/cli-multi-session-relay/design.md` D7 for the design
rationale, and `openspec/changes/cli-multi-session-relay/specs/cli-distribution/spec.md`
for the normative requirements.

```
dist/
├── README.md          # this file
├── npm/
│   ├── package.json    # template for the `@azula-app/cli` meta package
│   ├── bin/azula.js     # launcher: resolves + execs the platform binary
│   └── generate.mjs     # release-time generator: binaries dir -> 5 npm packages
└── homebrew/
    ├── azula.rb          # formula template (placeholders filled by the workflow)
    └── README.md         # tap repo layout + how the bump step works
```

## Name availability

Checked 2026-07-24 against the live registries (`curl` against
`crates.io/api/v1/crates/<name>` with a `User-Agent` header per crates.io's
API policy, and `registry.npmjs.org/<name>`):

| Registry  | Name                          | Status                                                          |
| --------- | ----------------------------- | ---------------------------------------------------------------- |
| crates.io | `azula`                       | **Available** — `{"errors":[{"detail":"crate \`azula\` does not exist"}]}` |
| crates.io | `azula-cli`                   | **Available** (checked as the D7 fallback; not needed)          |
| npm       | `@azula-app/cli`              | **Available** — chosen over the unscoped `azula-cli`; plain `azula` is taken by an unrelated 2019 package |
| npm       | `@azula-app/cli-darwin-arm64` | Returned `{"error":"Not found"}` for the package, which is expected whether or not the `azula-app` org exists — **the `azula-app` npm org must be created manually regardless** (see below); package names under it aren't independently reserved until first publish |

Both primary names from D7 are free, so **no fallback is needed right now**:
- crates.io crate: `azula` (binary `azula`, matches the existing package name
  in `Cargo.toml` — no rename).
- npm meta package: `@azula-app/cli`.

Re-check immediately before the *first* tagged release in case either name
gets claimed between now and then — `cargo publish -p azula` / `npm publish`
in the workflow will simply fail loudly if so, and this table needs a
follow-up edit plus a rename in `dist/npm/package.json`,
`dist/npm/generate.mjs` (the `SCOPE`/`META_NAME` constants and the
`@azula-app/cli-*` package names), `dist/npm/bin/azula.js` (the
`PLATFORM_PACKAGES` map), and `dist/homebrew/azula.rb`'s download URLs stay
unaffected either way since Homebrew doesn't go through a name registry.

**Fallbacks, if a name is claimed later** (per design D7):
- crates.io: publish as `azula-cli` instead of `azula` (also currently
  free) — would require renaming the `[package] name` in the root
  `Cargo.toml`, which is a breaking change for anyone who already ran
  `cargo install azula`, so prefer to catch this *before* the first release.
- npm: **taken** — the meta package now ships scoped as `@azula-app/cli`
  (decided 2026-07-26), so all five packages share the org namespace and
  none can be squatted. `azula` itself was already taken on npm by an
  unrelated 2019 package. The `npx` invocation is
  `npx -y @azula-app/cli mcp`.

## Manual setup before the first `v*` tag

The npm and Homebrew jobs are gated on repo **variables**
(`PUBLISH_NPM`, `PUBLISH_HOMEBREW`), so an unconfigured channel is skipped,
not a failure. They are deliberately NOT gated on `secrets.X != ''`: the
`secrets` context is unavailable in a job-level `if:`, and using it there
invalidates the entire workflow file — every run then fails at startup in
0s, including jobs unrelated to the gate. The
crates.io job uses OIDC and has nothing to gate on — it will run, and fail,
until its trusted publisher is configured. To light all three up:

1. **crates.io** — Trusted Publishing (OIDC), no long-lived token. There is
   a **bootstrap step**: crates.io only lets you configure a trusted
   publisher on a crate that already exists, so the very first publish must
   use an API token.

   a. Claim the name once, from a clean checkout of `main`:

      ```
      cargo login          # paste a token from https://crates.io/settings/tokens
      cargo publish -p azula --locked
      ```

      (Verify first with `cargo publish -p azula --dry-run` — it packages,
      then compiles the packaged tarball, so it catches anything the normal
      build wouldn't.)

   b. Then on <https://crates.io/crates/azula/settings> → Trusted
      Publishing → Add → GitHub, fill in:

      | Field             | Value        |
      |-------------------|--------------|
      | Repository owner  | `Azula-App`  |
      | Repository name   | `azula-cli`  |
      | Workflow filename | `release.yml`|
      | Environment       | *(leave empty)* |

   c. Revoke the bootstrap token at <https://crates.io/settings/tokens> —
      every later release authenticates over OIDC instead.

   The workflow filename is part of the identity crates.io matches, so
   **renaming `release.yml` breaks publishing** until the config is updated.
   Optionally set a GitHub Actions environment (e.g. `release`) with
   required reviewers and name it in both the job and the crates.io config
   for a manual approval gate on every publish.
2. **npm** — Trusted Publishing (OIDC), no `NPM_TOKEN`. Requires npm
   >= 11.5.1 and Node >= 22.14.0 (the workflow pins both). Two constraints
   shape the setup:

   - **A trusted publisher is configured per package**, and each package
     can only have one. This release ships **five** packages, so that's
     five configurations:

     | Package | |
     |---|---|
     | `@azula-app/cli` | the meta package users install |
     | `@azula-app/cli-darwin-arm64` | platform binary |
     | `@azula-app/cli-darwin-x64` | platform binary |
     | `@azula-app/cli-linux-x64` | platform binary |
     | `@azula-app/cli-linux-arm64` | platform binary |

   - **Same bootstrap as crates.io**: configuration lives on an existing
     package's settings page, so each package must be published once
     before OIDC can take over.

   Steps:

   a. Create the `azula-app` org on npmjs.com (needed for the scoped
      platform packages).

   b. Bootstrap all five once, from a tag whose GitHub Release already has
      the four binaries (so `v0.1.1` must be tagged first):

      ```
      gh release download v0.1.1 --dir bin-download-raw
      # unpack each azula-<version>-<target>.tar.gz into bin-download/<target>/
      node dist/npm/generate.mjs --version 0.1.1 --bin-dir bin-download --out-dir npm-out
      npm login
      for p in npm-out/cli-*/; do npm publish "$p" --access public; done
      npm publish npm-out/meta/ --access public
      ```

   c. For **each** of the five packages: npmjs.com → package → Settings →
      Trusted Publisher → GitHub Actions, with:

      | Field | Value |
      |---|---|
      | Organization or user | `Azula-App` |
      | Repository | `azula-cli` |
      | Workflow filename | `release.yml` |
      | Environment name | *(leave empty)* |

   d. Set the repo **variable** (Settings → Secrets and variables →
      Actions → Variables) `PUBLISH_NPM` = `true`. The job is gated on this
      rather than a secret, since OIDC leaves no secret to detect.

   Every later release then publishes over OIDC with **automatic provenance
   attestations** (the repo is public, so these succeed — see below).
3. **Homebrew**: create the `Azula-App/homebrew-azula` repo and a
   repo-scoped push token — see `dist/homebrew/README.md` for the full
   steps — add it as the `TAP_PUSH_TOKEN` repo secret, then set the repo
   variable `PUBLISH_HOMEBREW` = `true` to enable the job.

## Repo visibility

`Azula-App/azula-cli` is **public** (verified 2026-07-26), so nothing here
is visibility-blocked: npm's automatic provenance attestations work, end
users can fetch release assets from
`github.com/<repo>/releases/download/...` unauthenticated (which is how a
Homebrew install actually resolves), and the `repository` link on the
crates.io page resolves for visitors.

Keep it that way — turning the repo private again silently breaks Homebrew
installs at the *user's* machine rather than in CI (the workflow's own
downloads are authenticated via `gh`), and makes npm publishes fail
outright.

## Getting into homebrew-core

The tap (`Azula-App/homebrew-azula`) is the interim channel. Per
[Acceptable Formulae](https://docs.brew.sh/Acceptable-Formulae),
homebrew-core requires a DFSG-compatible open-source licence (azula is
`MIT OR Apache-2.0` — fine) and that "Upstream must identify the packaged
version as stable and provide an immutable tag or release" (the `v*` tag
flow satisfies this). Beyond that, notability is maintainer judgement
rather than a published numeric threshold — the current docs list no star
/ fork / watcher counts. All five azula repos are at 0 stars today, so the
tap is the realistic channel for now.

Also confirm the `Azula-App/azula-cli` GitHub repo (used throughout
`release.yml`, the npm package.json `repository` fields, and the Homebrew
formula's download URLs) is the actual final repo location — it's what
`git remote -v` in this worktree currently points to.
