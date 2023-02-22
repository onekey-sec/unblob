{
  description = "Extract files from any kind of container formats";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.filter.url = "github:numtide/nix-filter";
  inputs.pyperscan = {
    url = "git+https://github.com/vlaci/pyperscan?submodules=1";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.crane = {
    url = "github:ipetkov/crane";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.sasquatch = {
    url = "github:onekey-sec/sasquatch";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, filter, crane, pyperscan, sasquatch }:
    let
      # System types to support.
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Nixpkgs instantiated for supported system types.
      nixpkgsFor = forAllSystems (system: import nixpkgs {
        inherit system;
        overlays = [
          filter.overlays.default
          sasquatch.overlays.default
          self.overlays.default
        ];
      });
    in
    {
      overlays.default = import ./overlay.nix {
        inherit pyperscan crane;
      };
      packages = forAllSystems (system: rec {
        inherit (nixpkgsFor.${system}) unblob;
        default = unblob;
      });

      checks = forAllSystems (system: nixpkgsFor.${system}.unblob.tests);

      devShells = forAllSystems
        (system: {
          default = import ./shell.nix { pkgs = nixpkgsFor.${system}; };
        });

      legacyPackages = forAllSystems (system: nixpkgsFor.${system});
    };
}
