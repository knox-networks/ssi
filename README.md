# Self Sovereign Identity
Digital Identity Core


## Requirements
At the moment we make no promise to support anything but the latest version of Rust. Current minimum version of rust (MVR): 1.64

## Installation
You can utilize `ssi` by importing it via GitHub through the main branch. At the moment the crate is not published on crates.io
```
ssi = { git = "https://github.com/knox-networks/ssi", branch = "main" }
```


## Usage

## Running Tests
The tests can be run without any previous pre-configuration or pre-installation through the standard cargo command.

### Unit Tests

```rust
cargo test
```

### Spec Adherence
The spec adherence tests for Verifiable Credentials/Presentations, Cryptograhpic Suites, etc. have yet to be integrated.

## License
The Knox SSI library is licensed under the [Apache License](https://github.com/knox-networks/ssi/blob/main/LICENSE)
