{ system, python3, pyperscan }:

let
  self = python3.override {
    inherit self;
    packageOverrides = final: prev: {
      yaffshiv = final.callPackage ../yaffshiv { };
      pyperscan = pyperscan.packages.${system}.default.vectorscan;
    };
  };
in
self
