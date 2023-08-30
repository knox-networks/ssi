# Self Sovereign Identity
Digital Identity Core


## Requirements
At the moment we make no promise to support anything but the latest version of Rust. Current minimum version of rust (MVR): 1.64

## Installation
You can utilize `ssi` by importing it via GitHub through the main branch. At the moment the crate is not published on crates.io
```
ssi = { git = "https://github.com/knox-networks/ssi", branch = "main" }
```

### FFI
In order to build and run the FFI examples you will need to have the following installed:
```
cargo install --force cargo-make
```
We also need to add the appropriate targets to be run in various architectures and build artifacts accordingly.
```
rustup target add aarch64-apple-ios  (iOS devices)
rustup target add x86_64-apple-ios (iOS simulator for Swift unit tests)
rustup target add aarch64-apple-darwin (iOS simluator for Flutter unit tests)
cargo build --release --target aarch64-apple-ios --package ssi-ffi
cargo build --release --target x86_64-apple-ios --package ssi-ffi
cargo build --release --target aarch64-apple-darwin --package ssi-ffi
```
## Usage

## Running Tests
The tests can be run without any previous pre-configuration or pre-installation through the standard cargo command.

### Unit Tests

```rust
cargo test
```

### FFI Tests

```sh
cargo make ffi-test
```

### Spec Adherence
The spec adherence tests for Verifiable Credentials/Presentations, Cryptograhpic Suites, etc. have yet to be integrated.

## License
The Knox SSI library is licensed under the [Apache License](https://github.com/knox-networks/ssi/blob/main/LICENSE)
