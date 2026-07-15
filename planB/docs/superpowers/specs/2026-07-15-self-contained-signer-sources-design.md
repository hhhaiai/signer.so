# Self-contained signer source directories design

## Requirement

`/Users/sanbo/Desktop/api/qbdi/signer-implementations` contains three physical, independently
compilable source trees. A numbered directory must not depend on C++/Java source files stored in
`native-reimplementation/` or `unidbg-adjust-runner/`.

## Physical layout

```text
01-recovered-cpp/
  CMakeLists.txt
  src/recovered_primitives.cpp

02-vendor-jni-bridge/
  CMakeLists.txt
  include/*.h
  src/*.cpp
  tests/*.cpp

03-unidbg-runner/
  pom.xml
  src/main/java/**
  src/test/java/**
```

No source entry is a symbolic link. The original project files remain untouched and serve only as
the provenance snapshot from which the physical copies were made.

## Independent build rules

- Recovered C++ builds only `01-recovered-cpp/src/recovered_primitives.cpp`.
- Vendor bridge CMake builds only `02-vendor-jni-bridge/include`, `src`, and `tests`.
- Unidbg Maven builds only `03-unidbg-runner/pom.xml` and its local `src` tree.
- Build scripts calculate their directory from `BASH_SOURCE` and work from any current directory.
- External compilers, CMake, Android NDK, JDK, Maven local cache, official SOs, APKs, and caller JSON
  remain toolchain/runtime inputs rather than copied source.

## Verification

1. reject missing required source files;
2. reject source symlinks;
3. scan build scripts for references to the former canonical source directories;
4. strict compile recovered C++ with C++17 and warnings-as-errors;
5. build/test host bridge, audit exports/markers, and build Android arm64-v8a;
6. build the local Unidbg Maven tree offline and run the selected non-native tests;
7. do not execute recovered signing or load the target SO during verification.

## Accuracy boundary

Physical completeness means every directory contains all source and build configuration needed for
its declared executable or shared-library target. It does not change semantic coverage: the recovered
C++ snapshot still has documented unknown ARM64 FDEs, while the bridge and Unidbg routes require a
caller-provided local official SO for actual vendor behavior.
