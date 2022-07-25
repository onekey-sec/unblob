---
hide:
  - navigation
---

# Glossary

#### Handler

: a `Handler` in unblob is a Python class, which can detect and extract one
specific file format.

#### Extractor

: A tool which can extract a file format, e.g. 7zip, unrar. One tool might be used for multiple formats.

#### Hyperscan

: A high-performance multiple regex matching library by Intel: https://www.hyperscan.io/  
We are using it for finding specific bit/byte patterns like magic headers.

#### Unknown chunk

: A bytestream which none of our `Handler`s was able to recognize. They are
carved to separate files, with the filename including their start and end
offsets.
