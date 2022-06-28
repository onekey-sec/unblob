{ python310, hyperscan }:

let
  self = python310.override {
    inherit self;
    packageOverrides = final: prev: {
      arpy = final.callPackage ../arpy { };
      cstruct = final.callPackage ../cstruct { };
      dissect-cstruct = final.callPackage ../dissect-cstruct { };
      hyperscan = final.callPackage ../hyperscan { inherit hyperscan; };
      jefferson = final.callPackage ../jefferson { };
      plotext = final.callPackage ../plotext { };
      ubi-reader = final.callPackage ../ubi-reader { };
      yaffshiv = final.callPackage ../yaffshiv { };
    };
  };
in
self
