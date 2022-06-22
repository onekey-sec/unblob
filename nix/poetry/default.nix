# Here we define both the final application and an editable virtualenv
# for use during development, as they share common
# dependencies. Unfortunately `poetr2nix` defines quite different
# semantics for the two.


{ lib, mkShell, poetry2nix, stdenv, rustPlatform }:

let
  self = { projectDir, overrides, editablePackageSources, python, preferWheels ? false, ... }@args:

    let
      # pass all args which are not specific to mkPoetryEnv
      app = poetry2nix.mkPoetryApplication (builtins.removeAttrs args [ "editablePackageSources" ]);

      # pass args specific to mkPoetryEnv and all remaining arguments to mkDerivation
      editableEnv =
        stdenv.mkDerivation (
          {
            name = "${app.pname}-editable-env";
            src = poetry2nix.mkPoetryEnv {
              inherit projectDir editablePackageSources overrides preferWheels python;
            };

            installPhase = ''
              mkdir -p $out
              cp -a * $out
            '';

            # cargoSetupHook won't work for building the python environment
            nativeBuildInputs = builtins.filter
              (inp: inp != rustPlatform.cargoSetupHook)
              (args.nativeBuildInputs or [ ]);
          } // builtins.removeAttrs args [
            "editablePackageSources"
            "nativeBuildInputs"
            "overrides"
            "projectDir"
          ]
        );
    in
    app.overrideAttrs (super: {
      passthru = super.passthru // { inherit app editableEnv; };
    });
in
lib.makeOverridable self
