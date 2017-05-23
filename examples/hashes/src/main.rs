// ----------------------------------------------------------------------
//  Copyright (c) 2017 Hibari developers. All rights reserved.
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
extern crate md_5 as md5;
extern crate sha2;
extern crate sha3;

extern crate rand;
extern crate data_encoding;

use std::time::Instant;

// use digest::Digest;
use blake2::{Blake2s, Digest};
use md5::Md5;
use sha2::Sha256;
use sha3::Sha3_256;

use data_encoding::HEXLOWER;
use rand::{Rng, SeedableRng, XorShiftRng};

fn main() {
    let input_len = 8 * 1024 * 1024 * 1024;

    println!("Input data length: {:.2} GB", input_len as f64 / 1024.0 / 1024.0 / 1024.0);

    let elapse_md5 = hash::<Md5>(input_len, "MD5      ");
    let elapse_sha256 = hash::<Sha256>(input_len, "SHA-256  ");
    let elapse_sha3_256 = hash::<Sha3_256>(input_len, "SHA-3-256");
    let elapse_blake2 = hash::<Blake2s>(input_len, "Blake2s  ");

    println!("MD5: {:.2}x, SHA-256: 1.00x, SHA-3-256: {:.2}x, Blake2s: {:.2}x",
             elapse_sha256 / elapse_md5,
             elapse_sha256 / elapse_sha3_256,
             elapse_sha256 / elapse_blake2);
}

fn hash<D: Digest + Default>(input_len: usize, label: &str) -> f64 {
    let input = generate_input(input_len);
    let start = Instant::now();
    let mut hasher = D::default();
    hasher.input(&input[..]);
    let digest = hasher.result();
    let dur = Instant::now() - start;
    let nano_secs = dur.subsec_nanos() as f64 + dur.as_secs() as f64 * 1e9_f64;
    println!("{} - {:.2} seconds ({:.0} nano-seconds), digest: {:?}", 
             label,
             nano_secs / 1e9_f64, 
             nano_secs, 
             HEXLOWER.encode(&digest[..]));
    nano_secs
}

fn generate_input(len: usize) -> Vec<u8> {
    let mut rng = XorShiftRng::from_seed([0, 1, 2, 3]);
    rng.gen_iter().take(len).collect()
}
