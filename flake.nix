{
  description = "Extract files from any kind of container formats";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.utils.url = "github:numtide/flake-utils";
  inputs.filter.url = "github:numtide/nix-filter";
  inputs.pyperscan.url = "git+https://github.com/vlaci/pyperscan?submodules=1";

  inputs.sasquatch.url = "github:onekey-sec/sasquatch";
  inputs.sasquatch.flake = false;
  inputs.crane = {
    url = "github:ipetkov/crane";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, utils, filter, pyperscan, sasquatch, crane }:
    {
      overlays.default = import ./overlay.nix {
        inherit pyperscan sasquatch crane;
      };
    } //
    utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              filter.overlays.default
              self.overlays.default
            ];
          };
        in
        {
          packages = {
            inherit (pkgs) unblob sasquatch;
            default = pkgs.unblob;
          };

          devShells.default = import ./shell.nix { inherit pkgs; };

          legacyPackages = pkgs;
        }
      );
}
