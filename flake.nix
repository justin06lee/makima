# Nix flake for makima.
#
# Built from source with buildGoModule, which gives the same reproducibility
# guarantee the release archives aim at, checked by Nix rather than by hand.
{
  description = "Every machine you own, on one private network";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "makima";
          version = "0.0.0";

          src = ./.;

          # Replaced by `nix build` telling you the right value the first time
          # it is run against a new dependency set.
          vendorHash = pkgs.lib.fakeHash;

          subPackages = [
            "cmd/makima"
            "cmd/makimad"
            "cmd/makima-server"
            "cmd/makima-relay"
          ];

          ldflags = [ "-s" "-w" "-X" "main.version=${self.rev or "dirty"}" ];

          # The tests bind loopback sockets and start real WireGuard tunnels in
          # userspace. That works in the Nix sandbox; what does not is anything
          # reaching the network, so the STUN-dependent paths are skipped by
          # their own timeouts rather than by being excluded here.
          doCheck = true;

          meta = with pkgs.lib; {
            description = "Every machine you own, on one private network";
            homepage = "https://github.com/justin06lee/makima";
            license = licenses.mit;
            mainProgram = "makima";
            platforms = platforms.unix;
          };
        };

        devShells.default = pkgs.mkShell {
          packages = [ pkgs.go_1_25 pkgs.gopls pkgs.git ];
        };
      });
}
