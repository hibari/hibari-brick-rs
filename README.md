## hibari-brick-rs [![CircleCI](https://circleci.com/gh/hibari/hibari-brick-rs.svg?style=svg)](https://circleci.com/gh/hibari/hibari-brick-rs)

### A Fast, Embedded, Ordered Key-Value Store for Big and Small Values

**WARNING:** Work in progress. It will not be useful at all at this
moment.

**hibari-brick-rs** is a fast, embedded, ordered key-value store that
is excellent for storing a huge number of binary values in both small
and large sizes (as small as 8-bit integer and as large as few
megabytes).

It is written in [Rust programming language](http://rust-lang.org) and
intended to be embedded in Java VM and Erlang VM, although there is no
bindings for these languages yet.

It utilizes [RocksDB](http://rocksdb.org/) for storing key (including
user-defined metadata) and small values. Large values will be stored
in a log-based storage called "HLog". Unlike RocksDB, it will provide
API for handling large values, such as appending bytes to an existing
value and getting only a portion (a byte range) of a large value.


### Why Rust?

Rust is a modern systems programming language that runs blazingly
fast, prevents segfaults, and guarantees thread safety.

Rust does not have significant run-time environment such as garbage
collector. Instead, it gives us fine-grained control over memory
allocations, making it ideal to develop high-performance middleware
that can run with very low memory footprint.

Here, you will find brief case studies about Rust in production at
Dropbox and Mozilla (Firefox):

- https://blog.rust-lang.org/2016/05/16/rust-at-one-year.html#rust-in-production


### Requirements

- Unix-like operating system
  * Linux
  * FreeBSD
- Rust tool-chain
  * A *stable release* (1.13 or newer) is required.
  * Optionally, a *nightly build* of Rust to run a code-lint tool called
    "Clippy".
  * Use [rustup.rs](https://rustup.rs/) to install the latest stable
    release and a nightly build of Rust tool-chains.
  * More info about rustup.rs:
    [Taking Rust everywhere with rustup](https://blog.rust-lang.org/2016/05/13/rustup.html)
- Tools and libraries to build RocksDB
  * On Linux (Ubuntu), `sudo apt install gcc make libgflags-dev`
  * On FreeBSD, **TODO**


### Building and Running

```
# build and run unit tests
$ cargo test

# run a simple demo program
$ cargo run --release --example simple

# code lint
$ rustup run nightly cargo build --features=clippy
```


### Profiling with Valgrind

Install [Valgrind](http://valgrind.org/)

```
# Ubuntu
$ sudo apt install valgrind

# FreeBSD
$ sudo pkg install valgrind
```

Install cargo-profiler

```
$ cargo install cargo-profiler
```

Profiling

```
$ cargo build --release --example simple
$ cargo profiler callgrind --bin ./target/release/examples/simple -n 50
$ cargo profiler cachegrind --bin ./target/release/examples/simple -n 50
```


### Documentation

There is no documentation (including rustdoc) at this point as the API
will be changing everyday. Maybe you want to read source code in
[examples/simple.rs](https://github.com/hibari/hibari-brick-rs/blob/master/examples/simple.rs)
and
[src/lib.rs](https://github.com/hibari/hibari-brick-rs/blob/master/src/lib.rs)
to get basic idea of the API.


### License

```
Copyright (c) 2016-2018 Hibari developers.  All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```


### Note for License

Hibari has decided to display "Hibari developers" as the copyright
holder name in the source code files and manuals. Actual copyright
holder names (contributors) will be listed in the AUTHORS file.


_EOF_
