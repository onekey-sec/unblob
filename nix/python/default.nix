{ system, python3, pyperscan }:

let
  self = python3.override {
    inherit self;
    packageOverrides = final: prev: {
      pyperscan = pyperscan.packages.${system}.default.vectorscan;
      treelib = final.callPackage ../treelib { };
    };
  };
in
self
