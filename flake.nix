{
  description = "regolint";

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
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            go-outline
            gotools
            gopls
            open-policy-agent
            goreleaser
            golangci-lint
          ];

          shellHook = ''
            echo "regolint development environment!"
            echo ""
            echo "  go:         $(go version)"
            echo "  opa:        $(opa version | grep '^Version:' | cut -d' ' -f2)"
            echo "  goreleaser: $(goreleaser --version | head -1 | awk '{print $3}')"
            echo ""
          '';
        };
      }
    );
}
