inputs: final: prev:

{
  unblob = final.unblobPython.pkgs.callPackage ./nix/unblob { };
  sasquatch = prev.callPackage ./nix/sasquatch { inherit (prev) squashfsTools; src = inputs.sasquatch; };
  unblobPython = prev.callPackage ./nix/python { inherit (inputs) pyperscan; };
}
