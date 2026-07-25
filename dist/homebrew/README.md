# Homebrew tap

`azula` distributes over Homebrew via a separate **tap repository**,
`homebrew-azula`, rather than a formula in homebrew-core (core requires
notability/stability bars this project doesn't meet yet, and a tap lets the
release workflow push version bumps unattended).

## Tap repo layout

Create a GitHub repo named exactly `homebrew-azula` under the `Azula-App`
org (the `homebrew-` prefix is what makes `brew tap Azula-App/azula` resolve
to it — brew strips the prefix and lowercases). It needs just:

```
homebrew-azula/
└── Formula/
    └── azula.rb
```

Seed it once with a rendered copy of this directory's `azula.rb` template
(fill in a real version + shas manually, or just let the first tagged
release's workflow run create the file — either way).

Users install with:

```sh
brew tap azula-app/azula
brew install azula
# or, without a persistent tap:
brew install azula-app/azula/azula
```

## How the release workflow bumps it

`azula.rb` in *this* directory (`dist/homebrew/azula.rb`, in the
`azula-cli` repo) is a **template**, not the live formula. It has four
placeholders: `__VERSION__` and one `__SHA256_*__` per target. The
`publish-homebrew` job in `.github/workflows/release.yml`, on every `v*`
tag (gated on the `TAP_PUSH_TOKEN` secret being set):

1. Downloads the four `.sha256` files the `build-and-release` job already
   attached to the GitHub Release for that tag.
2. `sed`-substitutes `__VERSION__` and each `__SHA256_*__` placeholder with
   the real values.
3. Writes the result to `Formula/azula.rb` in a checkout of
   `Azula-App/homebrew-azula` (checked out using `TAP_PUSH_TOKEN`, since
   the default `GITHUB_TOKEN` only has access to the `azula-cli` repo
   itself).
4. Commits and pushes straight to the tap's default branch. No PR/review
   step — the tap is meant to always track the latest tagged release.

If the diff is empty (re-running a release, or a version already pushed by
hand), the commit step is skipped rather than pushing an empty commit.

## Manual setup (once, before the first release)

1. Create the `Azula-App/homebrew-azula` repo (can start empty; `Formula/`
   is created on first push if missing).
2. Mint a fine-grained GitHub PAT scoped to just that repo with
   **Contents: Read and write** permission (a classic PAT with `repo` scope
   also works, but is broader than necessary).
3. Add it as the `TAP_PUSH_TOKEN` secret on the `azula-cli` repo (Settings →
   Secrets and variables → Actions). Until this secret exists,
   `publish-homebrew` is skipped automatically — the release still succeeds,
   it just doesn't touch Homebrew.
