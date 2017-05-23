# A Simple Benchmark for Secure Hash Implementation in Rust

This is a very simple benchmark program to compare performance (speed)
between the following secure hash functions implemented in Rust:

- **SHA-256**
  * crates: [sha2](https://crates.io/crates/sha2) 0.5.2,
    [sha2-asm](https://crates.io/crates/sha2-asm) 0.2.1
- **SHA-3-256**
  * crate: [sha3](https://crates.io/crates/sha3) 0.5.1
- **Blake2s**
  * crate: [blake2](https://crates.io/crates/blake2) 0.5.2

It creates a `Vec<u8>` holding 8GB of random bytes, then calculate
secure hash using these hash functions, and compare time to complete.


## Running the Benchmark

```
$ cargo run --release
```

For example,

```
$ cargo run --release
...
Input data length: 8.00 GB
SHA-256   - 38.16 seconds (38162777286 nano-seconds), digest: "69de2109a91cd2dccf6d1ec447fa3975c0c44ab32459e178e31569bff09ce9d1"
SHA-3-256 - 74.51 seconds (74507281950 nano-seconds), digest: "8e41cb790bc5c80b3fe339f17d1b1c8871c0afe888a0e2692efbdc7e55656203"
Blake2s   - 18.57 seconds (18571153963 nano-seconds), digest: "ccae52d11f9e49ba565635be5e88533444392f869f9d0fc1b66d76bc85b33042"
SHA-256: 1.00x, SHA-3-256: 0.51x, Blake2s: 2.05x
```
