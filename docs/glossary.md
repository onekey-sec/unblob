---
hide:
  - navigation
---

# Glossary

#### Handler

: a `Handler` in unblob is a Python class, which can detect and extract a
specific file format.

#### Extractor

: A tool, which can extract a file format, e.g. `7z`, `unrar`, `jefferson`, etc.
One tool might be used for multiple formats.

#### Hyperscan

: A high-performance multiple regex matching library by Intel: https://www.hyperscan.io/  
We are using it for finding specific bit/byte pattern matching like magic headers.

#### Unknown chunk

: A byte stream which none of our `Handler`s was able to recognize. They are
carved to separate files, with the filename including their start and end
offsets.

#### Valid chunk

: A `ValidChunk` is something that one of the `Handler`s found and we can extract.

#### Recursion depth

: unblob is processing input files recursively, which means if we extracted a
file, that contains further files inside it, those will also be extracted, until
the recursion depth is reached. Beyond that level, no further extraction will
happen.  
For example, if a `tar.gz` contains a `zip` and a text file, the
recursion depth will be **3**: 1. gzip layer, 2. tar, 3. zip and text file.

#### MultiFile

A set of files that were identified by a `DirectoryHandler` representing a format
which consists of multiple files. `MultiFile` is extracted using a `DirectoryExtractor`
