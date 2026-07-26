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
│   ├── package.json    # template for the `azula-cli` meta package
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
| npm       | `azula-cli`                   | **Available** — registry returned `{"error":"Not found"}`       |
| npm       | `@azula-app/cli-darwin-arm64` | Returned `{"error":"Not found"}` for the package, which is expected whether or not the `azula-app` org exists — **the `azula-app` npm org must be created manually regardless** (see below); package names under it aren't independently reserved until first publish |

Both primary names from D7 are free, so **no fallback is needed right now**:
- crates.io crate: `azula` (binary `azula`, matches the existing package name
  in `Cargo.toml` — no rename).
- npm meta package: `azula-cli`.

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
- npm: publish the meta package scoped, e.g. `@azula-app/cli` or
  `@azula-app/azula-cli`, instead of the unscoped `azula-cli`. This changes
  the `npx` invocation to `npx -y @azula-app/cli mcp` — update the README
  Install section and the `mcp.json` example if this path is taken.

## Manual setup before the first `v*` tag

The npm and Homebrew jobs are gated on their secret existing (`if:` in
`release.yml`), so an unconfigured channel is skipped, not a failure. The
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
     | `azula-cli` | the meta package users install |
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
      npm publish npm-out/azula-cli/ --access public
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
   attestations** — which is why the repo visibility note below matters.
3. **Homebrew**: create the `Azula-App/homebrew-azula` repo and a
   repo-scoped push token — see `dist/homebrew/README.md` for the full
   steps — add it as the `TAP_PUSH_TOKEN` repo secret.

## Repo visibility gates two of the three channels

`Azula-App/azula-cli` is currently **private**. crates.io publishing is
unaffected (it uploads a self-contained tarball), but:

- **npm provenance** requires a public repository. Trusted Publishing
  generates provenance attestations automatically and cannot be opted out
  of, so `npm publish` fails from a private repo. npm therefore cannot go
  live until the repo is public.
- **Homebrew installs** fetch release assets from
  `github.com/<repo>/releases/download/...` **unauthenticated**, from the
  end user's machine. A private repo returns 404 for them, so a published
  formula would be broken even though the workflow that renders it succeeds
  (CI downloads are authenticated).
- The `repository` link on the published crates.io page also 404s for
  visitors while the repo is private.

homebrew-core (the eventual goal, pending notability) requires a public
repo as well.

Also confirm the `Azula-App/azula-cli` GitHub repo (used throughout
`release.yml`, the npm package.json `repository` fields, and the Homebrew
formula's download URLs) is the actual final repo location — it's what
`git remote -v` in this worktree currently points to.
