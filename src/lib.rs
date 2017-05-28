// ----------------------------------------------------------------------
//  Copyright (c) 2016-2017 Hibari developers. All rights reserved.
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

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;

extern crate blake2_rfc;
extern crate byteorder;
extern crate chrono;
extern crate data_encoding;
extern crate env_logger;
extern crate promising_future;
extern crate rand;
extern crate rmp_serde as rmps;
extern crate rocksdb;
extern crate serde;
extern crate timer;

use rmps::{Deserializer, Serializer};
use rocksdb::{DB, Options};
use serde::{Deserialize, Serialize};

use std::io;

// cargo rustc --lib -- -Z unstable-options --unpretty=''hir,typed'' (zsh)
// cargo rustc --lib -- -Z unstable-options --unpretty=hir,typed     (bash)
// cargo rustc --lib -- -Z unstable-options --unpretty=mir

pub mod hlog {
    pub mod hunk;
    pub mod wal;
    pub mod write_back;
}

pub use hlog::wal::BrickId;
use hlog::wal::{PutBlobResult, WalPosition, WalWriter};

pub type Etag = String;
// pub type Metadata
// pub type TTL

// TODO: Configurable
const MAIN_DB_PATH: &'static str = "/tmp/hibari-brick-test-data-rocksdb";

lazy_static! {
    static ref MAIN_DB: DB = {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        DB::open(&opts, MAIN_DB_PATH).unwrap()
    };
}

pub fn add_brick(brick_name: &str) -> BrickId {
    WalWriter::add_brick(brick_name)
}

pub fn get_brick_id(brick_name: &str) -> Option<BrickId> {
    WalWriter::get_brick_id(brick_name)
}

pub fn put(brick_id: BrickId, key: Vec<u8>, value: Vec<u8>) -> io::Result<()> {
    // write blob to WAL
    let future = WalWriter::put_value(brick_id, key.to_vec(), value);
    let PutBlobResult { storage_position, .. } = future.value().unwrap().unwrap();

    // write metadata to RocksDB
    let mut buf: Vec<u8> = Vec::new();
    storage_position.serialize(&mut Serializer::new(&mut buf)).unwrap();
    MAIN_DB.put(&key, &buf[..]).unwrap();

    Ok(())
}

pub fn get(brick_id: BrickId, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
    // read from RocksDB
    let res = MAIN_DB.get(key);
    let encoded_position = res.unwrap().unwrap();
    let mut decoder = Deserializer::new(&encoded_position[..]);
    let storage_position: WalPosition = Deserialize::deserialize(&mut decoder).ok().unwrap();

    WalWriter::get_value(brick_id, &storage_position)
}

pub fn shutdown() {
    WalWriter::shutdown();
}

#[cfg(test)]
mod tests {
    use super::{add_brick, get, put};
    use super::hlog::wal::WalWriter;

    #[test]
    fn test_put_get() {
        let brick_name = "brick1";
        let brick_id = add_brick(brick_name);

        put(brick_id, b"key1".to_vec(), b"val1".to_vec()).unwrap();
        put(brick_id, b"key2".to_vec(), b"val2".to_vec()).unwrap();

        let value2 = get(brick_id, b"key1");
        let mut expected = Vec::new();
        expected.extend_from_slice(b"val1");
        assert_eq!(expected, value2.unwrap().unwrap());

        let value3 = get(brick_id, b"key2");
        expected.clear();
        expected.extend_from_slice(b"val2");

        assert_eq!(expected, value3.unwrap().unwrap());

        WalWriter::shutdown();
    }

}
