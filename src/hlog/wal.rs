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

// TODO: Implement group commit.


use promising_future::{future_promise, Promise, Future};

use std::io::prelude::*;

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, SeekFrom};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::mpsc::{channel, Sender, SendError, Receiver};
use std::thread;

use blake2_rfc::blake2b::Blake2b;
use data_encoding::HEXLOWER;
use rmps::Serializer;
use serde::Serialize;

// use hlog::blob_store;
use hlog::hunk::{self, BinaryHunk, Blob, BlobWalHunk, Hunk, HunkSize, HunkType};

lazy_static! {
    // TODO: Configurable
    static ref WAL_PATH: PathBuf = {
        // "$HOME/hibari-brick-test-data/wal" or "/tmp/hibari-brick-test-data/wal"
        let mut path = PathBuf::from(env::var("HOME").unwrap_or("/tmp".to_string()));
        path.push("hibari-brick-test-data");

        super::super::utils::create_dir_if_missing(path.as_path())
            .expect(&format!("Could not create the WAL directory: {:?}", path));

        path.push("wal");
        path
    };

    static ref WAL_WRITER: WalWriter = WalWriter::new();
}

// Thread local for client threads
thread_local!(static LOCAL_Q: Sender<Request> = WAL_WRITER.queue.lock().unwrap().clone());

pub type SeqNum = u32;
pub type HunkOffset = u64;
pub type ValOffset = u32;
pub type Len = u32;

pub type BrickId = usize;

#[derive(Debug)]
pub enum Request {
    AddBrick(Promise<BrickId>, String),
    GetBrickId(Promise<Option<BrickId>>, String),
    PutBlob {
        brick_id: BrickId,
        key: Vec<u8>,
        value: Vec<u8>,
        hasher: Option<Blake2b>,
        promise: Promise<io::Result<PutBlobResult>>,
    },
    Flush(Promise<FlushPosition>),
    GetCurrentSeqNumAndDiskPos(Promise<(SeqNum, HunkOffset)>),
    Shutdown(Promise<bool>),
}

#[derive(Debug)]
pub struct BrickInfo {
    pub brick_name: String,
    pub head_seqnum: SeqNum,
    pub head_position: HunkOffset,
    pub writeback_seqnum: SeqNum,
}

#[derive(PartialEq, Debug)]
pub struct PutBlobResult {
    pub brick_name: String,
    pub storage_position: WalPosition,
}

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct WalPosition {
    wal_seqnum: SeqNum,
    wal_hunk_pos: HunkOffset,
    private_seqnum: SeqNum,
    private_hunk_pos: HunkOffset,
    val_offset: ValOffset,
    pub val_len: Len,
    pub checksum_string: Option<String>,
}

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct PrivateHLogPosition {
    seqnum: SeqNum,
    hunk_pos: HunkOffset,
    val_offset: ValOffset,
    pub val_len: Len,
    pub md5_string: Option<String>,
}

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct AllocatedPrivateHLogPosition {
    seqnum: SeqNum,
    hunk_pos: HunkOffset,
}

#[derive(Debug)]
pub struct FlushPosition {
    pos: u64,
}

pub struct WalWriter {
    queue: Mutex<Sender<Request>>,
}

impl WalWriter {
    fn new() -> Self {
        let (tx, rx) = channel();
        // TODO: Give a name to the thread. (Hint: Use thread builder)
        thread::spawn(move || {
            // let f = OpenOptions::new()
            //     .read(true)
            //     .write(true)
            //     .create(true)
            //     .open(WAL_PATH).unwrap();
            let f = File::create(WAL_PATH.as_path()).unwrap();
            let writer = BufWriter::new(f);
            handle_requests(rx, writer);
        });

        WalWriter { queue: Mutex::new(tx) }
    }

    pub fn add_brick(brick_name: &str) -> BrickId {
        let (future, prom) = future_promise();
        send(Request::AddBrick(prom, brick_name.to_string())).unwrap();
        future.value().unwrap()
    }

    pub fn get_brick_id(brick_name: &str) -> Option<BrickId> {
        let (future, prom) = future_promise();
        send(Request::GetBrickId(prom, brick_name.to_string())).unwrap();
        future.value().unwrap()
    }

    pub fn put_value(brick_id: BrickId, key: Vec<u8>, value: Vec<u8>) -> Future<io::Result<PutBlobResult>> {
        // if !NoChecksum

        let mut hasher = Blake2b::new(hunk::CHECKSUM_LEN);
        hasher.update(&value[..]);

        let (future, prom) = future_promise();
        let req = Request::PutBlob {
            brick_id: brick_id,
            key: key,
            value: value,
            hasher: Some(hasher),
            promise: prom,
        };
        send(req).unwrap();
        future
    }

    // Executed by the *client* thread
    pub fn get_value(_brick_id: BrickId,
                     wal_position: &WalPosition)
                     -> io::Result<Option<Vec<u8>>> {

        let position = wal_position.wal_hunk_pos + wal_position.val_offset as u64;

        // read blob (from HLog or WAL)
        let mut f = File::open(WAL_PATH.as_path())?;
        let mut pos = f.seek(SeekFrom::Start(position))?;
        if pos < position {
            WalWriter::flush();
            pos = f.seek(SeekFrom::Start(position))?;
        }
        assert_eq!(pos, position);

        let val_len = wal_position.val_len as u64;
        let mut chunk = f.take(val_len);
        let mut buf = Vec::with_capacity(val_len as usize);
        let mut size = chunk.read_to_end(&mut buf)?;
        if size < val_len as usize {
            WalWriter::flush();
            size = chunk.read_to_end(&mut buf)?;
        }
        assert_eq!(val_len as usize, size);

        // TODO: Verify the checksum

        Ok(Some(buf))
    }

    pub fn flush() {
        let (future, prom) = future_promise();
        send(Request::Flush(prom)).unwrap();
        future.value().unwrap();
    }

    pub fn get_current_seq_num_and_disk_pos() -> (SeqNum, HunkOffset) {
        let (future, prom) = future_promise();
        send(Request::GetCurrentSeqNumAndDiskPos(prom)).unwrap();
        future.value().unwrap()
    }

    pub fn open_wal_for_read(_seq_num: SeqNum) -> io::Result<BufReader<File>> {
        let f = File::open(WAL_PATH.as_path())?;
        Ok(BufReader::new(f))
    }

    pub fn shutdown() {
        let (future, prom) = future_promise();
        send(Request::Shutdown(prom)).unwrap();
        future.value().unwrap();
    }
}

// Drop will never be called because it is the WalWriter is bound to static?
impl Drop for WalWriter {
    fn drop(&mut self) {
        WalWriter::shutdown();
    }
}

fn send(req: Request) -> Result<(), SendError<Request>> {
    LOCAL_Q.with(|queue| queue.send(req))
}

fn handle_requests(rx: Receiver<Request>, mut writer: BufWriter<File>) {

    // State
    // let mut seq_num: SeqNum = 0u32;
    let mut pos: HunkOffset = 0u64;
    let mut brick_ids: HashMap<String, BrickId> = HashMap::new();
    let mut brick_info_v: Vec<BrickInfo> = Vec::new();

    // This will effectively start the WriteBack thread;
    super::write_back::WriteBack::poke();

    loop {
        match rx.recv().unwrap() {
            Request::AddBrick(promise, brick_name) => {
                let id = do_add_brick(&brick_name, &mut brick_ids, &mut brick_info_v);
                promise.set(id);
            }
            Request::GetBrickId(promise, brick_name) => {
                let maybe_id = brick_ids.get(&brick_name).map(|id| id.to_owned());
                promise.set(maybe_id);
            }
            Request::PutBlob { brick_id, key, value, hasher, promise } => {
                // TODO: Bound check
                let mut brick_info = &mut brick_info_v[brick_id];
                let brick_name = brick_info.brick_name.to_string();
                let result = do_put_blob(&mut writer, &mut pos, &mut brick_info, key, value, hasher)
                    .map(|wal_position| PutBlobResult {
                        brick_name: brick_name,
                        storage_position: wal_position,
                    });
                promise.set(result);
            }
            Request::Flush(promise) => {
                writer.flush().unwrap();
                promise.set(FlushPosition { pos: pos });
            }
            Request::GetCurrentSeqNumAndDiskPos(promise) => {
                // flush to ensure all bytes up to `pos` are available for reading.
                writer.flush().unwrap();
                promise.set((0, pos));
            }
            Request::Shutdown(promise) => {
                writer.flush().unwrap();
                super::write_back::WriteBack::shutdown();
                promise.set(true);
                break;  // exit from the event loop.
            }
        }
    }
}

fn do_add_brick(brick_name: &str,
                brick_ids: &mut HashMap<String, BrickId>,
                brick_info_v: &mut Vec<BrickInfo>)
                -> BrickId {
    let next_new_id = brick_info_v.len();
    let brick_id = brick_ids.entry(brick_name.to_owned()).or_insert(next_new_id);
    if *brick_id == next_new_id {
        let brick_info = BrickInfo {
            brick_name: brick_name.to_string(),
            head_seqnum: 0,
            head_position: 0,
            writeback_seqnum: 0,
        };
        brick_info_v.push(brick_info);
    }
    brick_id.to_owned()
}

fn do_put_blob(writer: &mut BufWriter<File>,
               mut pos: &mut HunkOffset,
               mut brick_info: &mut BrickInfo,
               key: Vec<u8>,
               value: Vec<u8>,
               hasher: Option<Blake2b>)
               -> io::Result<WalPosition> {
    let hunk_flags = Vec::new();
    let val_len = value.len() as Len;

    let private_seqnum = brick_info.head_seqnum;
    let mut private_hunk_pos = &mut brick_info.head_position;
    // TODO: Check if we want to increment the seqnum

    let private_hlog_pos = AllocatedPrivateHLogPosition {
        seqnum: private_seqnum,
        hunk_pos: *private_hunk_pos,
    };
    let mut encoded_pos: Vec<u8> = Vec::new();
    private_hlog_pos.serialize(&mut Serializer::new(&mut encoded_pos)).unwrap();

    let checksum =
        // if !NoChecksum
        if let Some(mut hasher) = hasher {
            hasher.update(&encoded_pos[..]);
            let digest = hasher.finalize();
            let mut result = [0u8; hunk::CHECKSUM_LEN];
            result.copy_from_slice(digest.as_bytes());
            Some(result)
        } else {
            None
        };

    let blobs = vec![Blob(value), Blob(key), Blob(encoded_pos)];

    let hunk = BlobWalHunk::new_with_checksum(&brick_info.brick_name, blobs, hunk_flags.clone(), checksum);
    // let maybe_checksum_string = hunk.md5.as_ref().map(|digest| HEXLOWER.encode(&digest[..]));
    let maybe_checksum_string = checksum.map(|digest| HEXLOWER.encode(&digest[..]));

    let BinaryHunk { hunk: binary_hunk, hunk_size, blob_index, .. } = hunk.encode();
    writer.write_all(&binary_hunk[..])?;

    let wal_position = WalPosition {
        wal_seqnum: 0,
        wal_hunk_pos: *pos,
        private_seqnum: private_seqnum,
        private_hunk_pos: *private_hunk_pos,
        val_offset: blob_index[0],
        val_len: val_len as Len,
        checksum_string: maybe_checksum_string,
    };
    let HunkSize { raw_size, padding_size, .. } =
        hunk::calc_hunk_size(&HunkType::BlobSingle, &hunk_flags, 0, 1, val_len);
    *pos += hunk_size as HunkOffset;
    *private_hunk_pos += raw_size as HunkOffset + padding_size as HunkOffset;
    Ok(wal_position)
}
