inputs: final: prev:

{
  unblob = final.unblobPython.pkgs.callPackage ./nix/unblob { };
  unblobPython = prev.callPackage ./nix/python { inherit (inputs) unblob-native pyperscan; };
  craneLib = inputs.crane.lib.${final.system};
}
