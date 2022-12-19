#!/usr/bin/env bash

# NOTE: The file structure will be different depending on your local environment.
cargo make ffi
# cargo make ffi-build
# cargo make ffi-header

# # Update Dart-SDK dynamic library
# cp ./target/release/libssi_ffi.dylib ~/Projects/KnoxNetworks/dart-sdk/dylib/libssi_ffi.dylib

# # NOTE: the dart-sdk needs to run `dart run ffigen` to generate the ssi_ffi.dart bindings file.
# cp ./ffi/headers/ssi_ffi.h ~/Projects/KnoxNetworks/dart-sdk/headers/ssi_ffi.h

# ### Update Flutter-SDK dynamic library
# cp ./target/i686-linux-android/release/libssi_ffi.so ~/Projects/KnoxNetworks/flutter-sdk/android/src/main/jniLibs/x86/libssi_ffi.so
# cp ./target/x86_64-linux-android/release/libssi_ffi.so ~/Projects/KnoxNetworks/flutter-sdk/android/src/main/jniLibs/x86_64/libssi_ffi.so
# cp ./target/aarch64-linux-android/release/libssi_ffi.so ~/Projects/KnoxNetworks/flutter-sdk/android/src/main/jniLibs/arm64-v8a/libssi_ffi.so
# cp ./target/armv7-linux-androideabi/release/libssi_ffi.so ~/Projects/KnoxNetworks/flutter-sdk/android/src/main/jniLibs/armeabi-v7a/libssi_ffi.so
