class Agentshield < Formula
  desc "Security runtime for AI coding agents"
  homepage "https://github.com/samet4k/agent-shield"
  url "https://github.com/samet4k/agent-shield/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "SKIP"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", "--path", "crates/agentshield-cli", "--root", prefix
    system "cargo", "install", "--path", "crates/agentshield-daemon", "--root", prefix
    (etc/"agentshield").install "policies/default.yml" => "policy.yml"
  end

  test do
    system "#{bin}/agentshield", "analyze", "echo hello"
  end
end