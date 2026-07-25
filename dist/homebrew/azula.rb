# Template for the `homebrew-azula` tap's Formula/azula.rb.
#
# This file is NOT itself the formula that ships to users — it's the
# template the release workflow's `publish-homebrew` job renders. The
# `__VERSION__` / `__SHA256_*__` placeholders below are substituted with
# `sed` from the just-published GitHub Release (see
# .github/workflows/release.yml's "Render Formula/azula.rb from the
# template" step, and dist/homebrew/README.md for the full mechanics).
#
# Do not hand-edit checksums here; they're always overwritten on release.
class Azula < Formula
  desc "Server-side companion CLI for the azula p2p app (pairing, messaging, terminal handoff, MCP server, relay)"
  homepage "https://azula.app"
  version "__VERSION__"
  license "MIT OR Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/Azula-App/azula-cli/releases/download/v__VERSION__/azula-__VERSION__-aarch64-apple-darwin.tar.gz"
      sha256 "__SHA256_AARCH64_APPLE_DARWIN__"
    end
    on_intel do
      url "https://github.com/Azula-App/azula-cli/releases/download/v__VERSION__/azula-__VERSION__-x86_64-apple-darwin.tar.gz"
      sha256 "__SHA256_X86_64_APPLE_DARWIN__"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Azula-App/azula-cli/releases/download/v__VERSION__/azula-__VERSION__-aarch64-unknown-linux-musl.tar.gz"
      sha256 "__SHA256_AARCH64_UNKNOWN_LINUX_MUSL__"
    end
    on_intel do
      url "https://github.com/Azula-App/azula-cli/releases/download/v__VERSION__/azula-__VERSION__-x86_64-unknown-linux-musl.tar.gz"
      sha256 "__SHA256_X86_64_UNKNOWN_LINUX_MUSL__"
    end
  end

  def install
    bin.install "azula"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/azula --version")
  end
end
