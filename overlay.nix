inputs: final: prev:

{
  inherit (final.python3.pkgs) unblob;
  _sources = final.callPackage ./nix/_sources/generated.nix { };

  # Lief 12.3 incompatibility with Cmake 3.26
  lief = prev.lief.overrideAttrs (super: {
    postPatch = ''
      substituteInPlace setup.py \
        --replace \
                  'cmake_args = ["-DLIEF_FORCE_API_EXPORTS=ON", "-DLIEF_PYTHON_API=on"]' \
                  'cmake_args = ["-DLIEF_FORCE_API_EXPORTS=ON", "-DLIEF_PYTHON_API=on", "-DLIEF_EXAMPLES=off"]'
    '';
  });

  # Own package updated independently of nixpkgs
  jefferson = final.callPackage ./nix/jefferson { };

  python3 = prev.python3 // {
    pkgs = prev.python3.pkgs.overrideScope
      (pyFinal: pyPrev: {
        # Own package updated independently of nixpkgs
        lzallright = pyFinal.callPackage ./nix/lzallright { };

        # Own package updated independently of nixpkgs
        pyperscan = inputs.pyperscan.packages.${final.system}.default.vectorscan;

        # Missing from nixpkgs
        treelib = pyFinal.callPackage ./nix/treelib { };

        # The reason for everything
        unblob = pyFinal.callPackage ./nix/unblob { };

        # Own package updated independently of nixpkgs
        unblob-native = inputs.unblob-native.packages.${final.system}.default;
      });
  };

  # Existing alias is rebound to the updated package set for consistence
  python3Packages = final.python3.pkgs;

  # Own package updated independently of nixpkgs
  ubi_reader = final.callPackage ./nix/ubi_reader { };
}
