{ system, python3, pyperscan }:

let
  self = python3.override {
    inherit self;
    packageOverrides = final: prev: {
      cstruct = final.callPackage ../cstruct { };
      jefferson = final.callPackage ../jefferson { };
      plotext = final.callPackage ../plotext { };
      ubi-reader = final.callPackage ../ubi-reader { };
      yaffshiv = final.callPackage ../yaffshiv { };
      pyperscan = pyperscan.packages.${system}.default.vectorscan;
    };
  };
in
self
