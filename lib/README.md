<h1 align="center">Huiz</h1>
<div align="center">
 <strong>
   Whois implementation in rust
 </strong>
</div>

<div align="center">
  <!-- Github Actions -->
  <a href="https://github.com/namecare/huiz/actions/workflows/rust.yml?query=branch%3Amaster">
    <img src="https://img.shields.io/github/actions/workflow/status/namecare/huiz/rust.yml?branch=master&style=flat-square"
      alt="actions status" />
  </a>
  <!-- Version -->
  <a href="https://crates.io/crates/huiz">
    <img src="https://img.shields.io/crates/v/huiz.svg?style=flat-square"
    alt="Crates.io version" />
  </a>
  <!-- Docs -->
  <a href="https://docs.rs/huiz">
    <img src="https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square"
      alt="docs.rs docs" />
  </a>
  <!-- Downloads -->
  <a href="https://crates.io/crates/huiz">
    <img src="https://img.shields.io/crates/d/huiz.svg?style=flat-square"
      alt="Download" />
  </a>
</div>

Huiz is a lightweight Rust crate featuring WHOIS client that is inspired by [rfc1036/whois](https://github.com/rfc1036/whois) and [FreeBSD/whoid](https://github.com/apple-oss-distributions/adv_cmds/blob/320b8e327652c75d74e60adb9d085f4a81ac3d9d/whois/whois.c#L477).

## Install
```toml
# Cargo.toml
[dependencies]
huiz = "0.1.0"
```

### Quickstart

NOTE: these examples are for the 0.1 release.

```rust
use huiz::whois;

fn main() {
    let domain = "example.com";
    let r = whois(domain).unwrap();
    println!("{:?}", r)
}
```

## License

Licensed under either of

-   Apache License, Version 2.0
    ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
-   MIT license
    ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any Contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.