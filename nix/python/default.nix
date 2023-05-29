{ system, python3, pyperscan, unblob-native }:

let
  self = python3.override {
    inherit self;
    packageOverrides = final: prev: {
      pyperscan = pyperscan.packages.${system}.default.vectorscan;
      unblob-native = unblob-native.packages.${system}.default;
      treelib = final.callPackage ../treelib { };
      lzallright = final.callPackage ../lzallright { };
      ubi_reader = final.callPackage ../ubi_reader { };
      jefferson = final.callPackage ../jefferson { };
    };
  };
in
self
