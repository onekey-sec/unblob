{ system, python310, pyperscan }:

let
  self = python310.override {
    inherit self;
    packageOverrides = final: prev: {
      arpy = final.callPackage ../arpy { };
      cstruct = final.callPackage ../cstruct { };
      dissect-cstruct = final.callPackage ../dissect-cstruct { };
      jefferson = final.callPackage ../jefferson { };
      plotext = final.callPackage ../plotext { };
      ubi-reader = final.callPackage ../ubi-reader { };
      yaffshiv = final.callPackage ../yaffshiv { };
      pyperscan = pyperscan.packages.${system}.default.vectorscan;
    };
  };
in
self
