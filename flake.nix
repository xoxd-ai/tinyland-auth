{
  description = "@tummycrypt/tinyland-auth — autonomous identity management for tinyland";

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
            bazel_8
            just
            nodejs_22
            (pnpm_10 or pnpm)
          ];
          shellHook = ''
            echo "tinyland-auth dev shell"
            echo "  node $(node --version)"
            echo "  pnpm $(pnpm --version)"
            echo "  bazel $(bazel --version | head -n1)"
          '';
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
