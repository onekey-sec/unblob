{ system, python3, pyperscan }:

let
  self = python3.override {
    inherit self;
    packageOverrides = final: prev: {
      arpy = final.callPackage ../arpy { };
      cstruct = final.callPackage ../cstruct { };
      jefferson = final.callPackage ../jefferson { };
      lief = prev.lief.overrideAttrs (super: {
        meta.platform = super.meta.platform ++ [ final.lib.platforms.darwin ];
      });
      plotext = final.callPackage ../plotext { };
      ubi-reader = final.callPackage ../ubi-reader { };
      yaffshiv = final.callPackage ../yaffshiv { };
      pyperscan = pyperscan.packages.${system}.default.vectorscan;
    };
  };
in
self
