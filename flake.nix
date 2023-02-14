{
  description = "Extract files from any kind of container formats";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.utils.url = "github:numtide/flake-utils";
  inputs.filter.url = "github:numtide/nix-filter";
  inputs.pyperscan.url = "github:vlaci/pyperscan";

  inputs.sasquatch.url = "github:onekey-sec/sasquatch";
  inputs.sasquatch.flake = false;

  outputs = { self, nixpkgs, utils, filter, pyperscan, sasquatch }:
    {
      overlays.default =
        import ./overlay.nix { inherit pyperscan sasquatch; }
      ;
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
