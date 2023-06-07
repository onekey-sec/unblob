inputs: final: prev:

{
  inherit (final.python3.pkgs) unblob;
  python3 = prev.python3 // {
    pkgs = prev.python3.pkgs.overrideScope
      (pyFinal: pyPrev: {
        pyperscan = inputs.pyperscan.packages.${final.system}.default.vectorscan;
        unblob-native = inputs.unblob-native.packages.${final.system}.default;
        treelib = pyFinal.callPackage ./nix/treelib { };
        lzallright = pyFinal.callPackage ./nix/lzallright { };
        ubi_reader = pyFinal.callPackage ./nix/ubi_reader { };
        jefferson = pyFinal.callPackage ./nix/jefferson { };
        unblob = pyFinal.callPackage ./nix/unblob { };
      });
  };
  python3Packages = final.python3.pkgs;
}
