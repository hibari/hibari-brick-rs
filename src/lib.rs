#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

#[macro_use]
extern crate lazy_static;

extern crate byteorder;
extern crate crypto;
extern crate promising_future;
extern crate rmp_serialize as msgpack;
extern crate rocksdb;
extern crate rustc_serialize;

use msgpack::{Encoder, Decoder};
use rocksdb::{DB, Options, Writable};
use rustc_serialize::{Encodable, Decodable};

use std::io;

pub mod hlog {
    pub mod hunk;
    pub mod wal;
}

pub use hlog::wal::BrickId;
use hlog::wal::{PutBlobResult, WalPosition, WalWriter};

// Type Defs

pub type Etag = String;
// pub type Metadata
// pub type TTL

// Consts / Statics

// TODO: Configurable
const MAIN_DB_PATH: &'static str = "/home/tatsuya/tmp/hibari_storage_test";

lazy_static! {
    static ref MAIN_DB: DB = {
        let mut opts = Options::new();
        opts.create_if_missing(true);

        DB::open(&opts, MAIN_DB_PATH).unwrap()
    };
}

// Structs

// Public API

pub fn add_brick(brick_name: &str) -> BrickId {
    WalWriter::add_brick(brick_name)
}

pub fn get_brick_id(brick_name: &str) -> Option<BrickId> {
    WalWriter::get_brick_id(brick_name)
}

pub fn put(brick_id: BrickId, key: Vec<u8>, value: Vec<u8>) -> io::Result<Etag> {
    // clone the key for RocksDB
    let key2 = &key.to_vec();

    // write blob to WAL
    let future = WalWriter::put_value(brick_id, key, value);
    let PutBlobResult { storage_position, .. } = future.value().unwrap();

    // write metadata to RocksDB
    let mut buf: Vec<u8> = Vec::new();
    storage_position.encode(&mut Encoder::new(&mut buf)).unwrap();
    MAIN_DB.put(key2, &buf[..]).unwrap();

    Ok(storage_position.md5_string.unwrap_or("".to_string()))
}

pub fn get(brick_id: BrickId, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
    // read from RocksDB
    let res = MAIN_DB.get(key);
    let encoded_position = res.unwrap().unwrap();
    let mut decoder = Decoder::new(&encoded_position[..]);
    let storage_position: WalPosition = Decodable::decode(&mut decoder).ok().unwrap();

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

        let etag = put(brick_id, b"key1".to_vec(), b"val1".to_vec());
        assert_eq!("8de92ce2033cf3ca03fa8cc63e7a703f".to_string(),
                   etag.unwrap());

        let _etag3 = put(brick_id, b"key2".to_vec(), b"val2".to_vec());

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
