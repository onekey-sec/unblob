{
  description = "Extract files from any kind of container formats";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.poetry2nix.url = "github:nix-community/poetry2nix";

  inputs.sasquatch.url = "github:IoT-Inspector/sasquatch";
  inputs.sasquatch.flake = false;

  outputs = { self, nixpkgs, poetry2nix, sasquatch }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ self.overlay ];
      };
      inherit (pkgs) unblob;
    in
    {
      overlay = nixpkgs.lib.composeManyExtensions [
        poetry2nix.overlay
        (import ./overlay.nix { inherit sasquatch; })
      ];

      packages.${system} = {
        inherit unblob;
        inherit (pkgs) sasquatch;
      };

      defaultPackage.${system} = unblob;

      devShell.${system} = pkgs.mkShell {
        packages = [ unblob.editableEnv unblob.runtimeDeps ];
      };
    };
}
