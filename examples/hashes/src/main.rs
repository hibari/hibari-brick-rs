// ----------------------------------------------------------------------
//  Copyright (c) 2018 Hibari developers. All rights reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
// ----------------------------------------------------------------------

extern crate blake2;
extern crate blake2_rfc;
extern crate md_5 as md5;
extern crate sha2;
extern crate sha3;

extern crate data_encoding;
extern crate rand;

use std::time::Instant;

// use digest::Digest;
use blake2::{Blake2b, Blake2s, Digest};
use blake2_rfc::blake2b::blake2b;
use md5::Md5;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

use data_encoding::HEXLOWER;
use rand::{Rng, SeedableRng, XorShiftRng};

const GB: usize = 1024 * 1024 * 1024;

fn main() {
    let input_len = 8 * GB;
    // let input_len = 1024 * 1024;
    let input = generate_input(input_len);

    let dur_md5 =      hash::<Md5>(&input[..],      "MD5 (asm)     ");
    let dur_sha256 =   hash::<Sha256>(&input[..],   "SHA-256 (asm) ");
    let dur_sha3_256 = hash::<Sha3_256>(&input[..], "SHA-3-256     ");
    let dur_blake2s =  hash::<Blake2s>(&input[..],  "Blake2s       ");
    let dur_blake2b_rfc = hash_blake2b_rfc(&input[..]);
    let dur_sha512 =   hash::<Sha512>(&input[..],   "SHA-512 (asm) ");
    let dur_sha3_512 = hash::<Sha3_512>(&input[..], "SHA-3-512     ");
    let dur_blake2b =  hash::<Blake2b>(&input[..],  "Blake2b       ");

    println!(
        r"
Speed ups:
  MD5 (asm):     {:.2}x
  SHA-256 (asm): 1.00x
  SHA-3-256:     {:.2}x
  Blake2s (256)  {:.2}x
  Blake2b (256): {:.2}x
  SHA-512 (asm): {:.2}x
  SHA-3-512:     {:.2}x
  Blake2b (512): {:.2}x",
        dur_sha256 / dur_md5,
        dur_sha256 / dur_sha3_256,
        dur_sha256 / dur_blake2s,
        dur_sha256 / dur_blake2b_rfc,
        dur_sha256 / dur_sha512,
        dur_sha256 / dur_sha3_512,
        dur_sha256 / dur_blake2b
    );
}

fn generate_input(len: usize) -> Vec<u8> {
    println!(
        "Generating a random input data (length: {:.2} GB)",
        len as f64 / GB as f64
    );

    let start = Instant::now();

    let mut rng = XorShiftRng::from_seed([0, 1, 2, 3]);
    let input = rng.gen_iter().take(len).collect();

    let dur = Instant::now() - start;
    let nano_secs = dur.subsec_nanos() as f64 + dur.as_secs() as f64 * 1e9_f64;
    println!(
        "Generated the random input data in {:.2} seconds ({:.0} nano-seconds)\n",
        nano_secs / 1e9_f64,
        nano_secs
    );
    input
}

fn hash<D: Digest + Default>(input: &[u8], label: &str) -> f64 {
    let start = Instant::now();

    let mut hasher = D::default();
    hasher.input(&input[..]);
    let digest = hasher.result();

    let dur = Instant::now() - start;
    let nano_secs = dur.subsec_nanos() as f64 + dur.as_secs() as f64 * 1e9_f64;
    println!(
        "{} - {:.2} seconds ({:.0} nano-seconds), digest: {:?}",
        label,
        nano_secs / 1e9_f64,
        nano_secs,
        HEXLOWER.encode(&digest[..])
    );
    nano_secs
}

fn hash_blake2b_rfc(input: &[u8]) -> f64 {
    let start = Instant::now();

    let digest = blake2b(32, &[], input);

    let dur = Instant::now() - start;
    let nano_secs = dur.subsec_nanos() as f64 + dur.as_secs() as f64 * 1e9_f64;
    println!(
        "Blake2b (256): - {:.2} seconds ({:.0} nano-seconds), digest: {:?}",
        nano_secs / 1e9_f64,
        nano_secs,
        HEXLOWER.encode(digest.as_bytes())
    );
    nano_secs
}
