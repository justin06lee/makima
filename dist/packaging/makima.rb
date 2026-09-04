# Homebrew formula for makima.
#
# Lives here rather than in a tap repository so it is versioned with the code
# it installs. The release workflow rewrites the version and the four checksums
# and pushes the result to the tap, so this file is the source of truth and the
# tap is a copy.
#
# Deliberately does not install a service. `brew services start makima` would
# enable a daemon at boot that takes over a network interface and edits the
# routing table, on a machine somebody may only be trying out. `makima up` asks
# for that explicitly; a package manager should not decide it for them.
class Makima < Formula
  desc "Every machine you own, on one private network"
  homepage "https://github.com/justin06lee/makima"
  version "0.0.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/justin06lee/makima/releases/download/v#{version}/makima-v#{version}-darwin-arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/justin06lee/makima/releases/download/v#{version}/makima-v#{version}-darwin-amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/justin06lee/makima/releases/download/v#{version}/makima-v#{version}-linux-arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/justin06lee/makima/releases/download/v#{version}/makima-v#{version}-linux-amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "makima", "makimad", "makima-server", "makima-relay"
  end

  def caveats
    <<~EOS
      makima installs four binaries and starts nothing.

      To see it work without touching anything on this machine:
        makima try -serve 8080

      To bring up a real mesh, which needs root because it creates a network
      interface and edits the routing table:
        sudo makima up
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/makima version")
  end
end
