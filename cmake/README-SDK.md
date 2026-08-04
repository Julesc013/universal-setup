# Universal Setup C SDK

Universal Setup 1.0.0 installs the implemented USK C ABI 1.0, static and shared
libraries, public headers, public schemas, the reviewed ABI manifest, and
relocatable CMake package metadata.

```cmake
find_package(UniversalSetup 1.0.0 EXACT CONFIG REQUIRED)
target_link_libraries(my_consumer PRIVATE UniversalSetup::CoreStatic)
```

Use `UniversalSetup::CoreShared` for the shared library. Its imported target
propagates the Windows `USK_USE_SHARED` declaration automatically. Consumers
that only inspect declarations can use `UniversalSetup::Headers`.

The installed `usu` headers preserve the existing neutral interface vocabulary
but do not represent an implemented or exported `usu` runtime. The supported
compiled SDK surface is the four `usk_*_v1` functions recorded in the ABI
manifest. Private C++ lifecycle, archive, transaction, state, and policy types
are not installed or exported as SDK targets.

The CMake package version, C ABI version, and contract maturity are separate:
the package is 1.0.0, the C ABI is 1.0, and the product-package and setup-recipe
contracts remain fixture-qualified. Installing this SDK grants no acquisition,
network, credential, live-mutation, consumer-adoption, signing, publication, or
product authority.
