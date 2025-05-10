# miku-ktls-sys

[![Crates.io](https://img.shields.io/crates/v/miku-ktls-sys)](https://crates.io/crates/miku-ktls-sys)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

`include/uapi/linux/tls.h` bindings, for TLS kernel offload.

Generated with `bindgen tls.h -o src/bindings.rs`.

See <https://github.com/hanyu-dev/miku-ktls> for a higher-level / safer interface.

## MSRV

1.77.0

## License

This project is primarily distributed under the terms of both the MIT license
and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
