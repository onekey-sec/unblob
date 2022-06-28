{
  description = "Extract files from any kind of container formats";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.poetry2nix.url = "github:nix-community/poetry2nix";
  inputs.poetry2nix.inputs.nixpkgs.follows = "nixpkgs";
  inputs.pyperscan.url = "github:vlaci/pyperscan";

  inputs.sasquatch.url = "github:onekey-sec/sasquatch";
  inputs.sasquatch.flake = false;

  outputs = { self, nixpkgs, poetry2nix, pyperscan, sasquatch }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ self.overlays.default ];
      };
      inherit (pkgs) unblob;
    in
    {
      overlays.default = nixpkgs.lib.composeManyExtensions [
        poetry2nix.overlay
        (import ./overlay.nix { inherit system pyperscan sasquatch; })
      ];

      packages.${system} = {
        inherit unblob;
        inherit (pkgs) sasquatch;
        default = unblob;
      };

      devShells.${system}.default = import ./shell.nix { inherit pkgs; };

      legacyPackages.${system} = pkgs;
    };
}
