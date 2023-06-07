inputs: final: prev:

{
  inherit (final.python3.pkgs) unblob;
  _sources = final.callPackage ./nix/_sources/generated.nix { };
  ubi_reader = final.callPackage ./nix/ubi_reader { };
  jefferson = final.callPackage ./nix/jefferson { };
  python3 = prev.python3 // {
    pkgs = prev.python3.pkgs.overrideScope
      (pyFinal: pyPrev: {
        pyperscan = inputs.pyperscan.packages.${final.system}.default.vectorscan;
        unblob-native = inputs.unblob-native.packages.${final.system}.default;
        treelib = pyFinal.callPackage ./nix/treelib { };
        lzallright = pyFinal.callPackage ./nix/lzallright { };
        unblob = pyFinal.callPackage ./nix/unblob { };
      });
  };
  python3Packages = final.python3.pkgs;
}
