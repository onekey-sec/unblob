{ squashfsTools }:

squashfsTools.overrideAttrs (super: {
  patches = super.patches ++ [
    ./0001-Unsquash-3-Fix-segmentation-fault-in-read_inode.patch
  ];
})
