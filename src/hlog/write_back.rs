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

use chrono;
use promising_future::{future_promise, Promise};
use rmps::Deserializer;
use serde::Deserialize;
use timer;

use std::io::prelude::*;

use std::io::{self, SeekFrom};

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::sync::mpsc::{channel, Sender, SendError, Receiver};
use std::thread;

use super::hunk::{self, BinaryHunk, BlobSingleHunk, BlobWalHunk, BoxedHunk, CHECKSUM_LEN, Hunk};
use super::wal::{AllocatedPrivateHLogPosition, HunkOffset, SeqNum, WalWriter};

// TODO: Configurable
pub const PRIVATE_BLOB_PATH: &'static str = "/tmp/hibari-brick-test-data-blob-";
pub const WRITE_BACK_INTERVAL_SECS: i64 = 2;

lazy_static! {
    static ref WRITE_BACK: WriteBack = WriteBack::new();
    static ref IS_WRITE_BACK_RUNNING: AtomicBool = AtomicBool::new(false);
}

// Thread local for client threads
thread_local!{
    static LOCAL_Q: Sender<Request> = WRITE_BACK.queue.lock().unwrap().clone();
}

#[derive(Debug)]
pub enum Request {
    Poke,
    WriteBack,
    // FullWriteBack(Promise<bool>), // No need for full write back because
                                     // keys/metadata are not in the WAL.
    Shutdown(Promise<bool>),
}

struct WriteBackRecord {
    hunk: Vec<u8>,
    hunk_size: u32,
    key: Vec<u8>,
    pos: AllocatedPrivateHLogPosition,
}

pub struct WriteBack {
    queue: Mutex<Sender<Request>>,
}

impl WriteBack {
    fn new() -> Self {
        let (tx, rx) = channel();

        // TODO: Give a name to the threads. (Hint: Use thread builder)
        thread::spawn(move || handle_requests(&rx));
        WriteBack { queue: Mutex::new(tx) }
    }

    pub fn poke() {
        send(Request::Poke).unwrap();
    }

    pub fn shutdown() {
        let (future, prom) = future_promise();
        send(Request::Shutdown(prom)).unwrap();
        future.value().unwrap();
    }
}

// Drop will never be called because the WriteBack is bound to static :(
impl Drop for WriteBack {
    fn drop(&mut self) {
        WriteBack::shutdown();
    }
}

fn send(req: Request) -> Result<(), SendError<Request>> {
    LOCAL_Q.with(|queue| queue.send(req))
}

fn handle_requests(rx: &Receiver<Request>) {
    // State
    // let mut last_seq_num: SeqNum = 0u32;
    let mut last_pos: HunkOffset = 0u64;
    let write_back_block_size = 20 * 1024 * 1024; // 20MB.
    let write_back_interval = chrono::Duration::seconds(WRITE_BACK_INTERVAL_SECS);
    let _writer_back_scheduler = start_write_back_scheduler(write_back_interval);

    loop {
        match rx.recv().unwrap() {
            Request::Poke => (),
            Request::WriteBack => match write_back_wals(last_pos, write_back_block_size) {
                Ok(new_pos) => last_pos = new_pos,
                Err(err) => println!("Write back failed with error: {:?}", err),
            },
            Request::Shutdown(promise) => {
                promise.set(true);
                break; // exit from the event loop.
            }
        }
    }
}

fn start_write_back_scheduler(interval: chrono::Duration) -> (timer::Timer, timer::Guard) {
    let timer = timer::Timer::new();
    // holding the guard seems required, otherwise timer will never go off.
    let guard = timer.schedule_repeating(interval, || 
        if !IS_WRITE_BACK_RUNNING.load(Ordering::Relaxed) {
            let _ignore = send(Request::WriteBack); // avoid unwrapping here.
        });
    (timer, guard)
}

fn write_back_wals(last_pos: HunkOffset, block_size: u64) -> io::Result<HunkOffset> {
    debug!("Writeback started.");
    IS_WRITE_BACK_RUNNING.store(true, Ordering::Relaxed);

    // let seq_nums = WalWriter:get_all_seq_nums();
    let (cur_seq_num, cur_pos) = WalWriter::get_current_seq_num_and_disk_pos();
    let new_pos = write_back_wal(cur_seq_num, last_pos, cur_pos, block_size)?;

    IS_WRITE_BACK_RUNNING.store(false, Ordering::Relaxed);
    debug!("Writeback finished.");

    Ok(new_pos)
}

fn write_back_wal(seq_num: SeqNum,
                  start_pos: HunkOffset,
                  end_pos: HunkOffset, 
                  block_size: u64) -> io::Result<HunkOffset> {
    let mut f = WalWriter::open_wal_for_read(seq_num)?;
    let mut cur_pos = f.seek(SeekFrom::Start(start_pos))?;
    assert_eq!(cur_pos, start_pos);

    let mut buf = vec![0u8; block_size as usize];
    let mut read_offset = 0;

    while cur_pos < end_pos {
        let actual_size = f.read(&mut buf[read_offset..])? as u64;
        debug!("Writeback: read {} bytes from WAL({}).", actual_size, seq_num);

        cur_pos += actual_size;
        let bytes_to_parse = ::std::cmp::min(block_size as usize, read_offset + actual_size as usize);

        match write_back_block(&buf[..bytes_to_parse as usize]) {
            Ok(next_offset) => {
                read_offset = next_offset;
            }
            Err(..) => panic!("Writeback: Could not parse hunks"), // TODO: Propagate the error.
        }
        let remaining_len = bytes_to_parse - read_offset;
        if remaining_len == 0 {
            read_offset = 0;
        } else {
            let (distination, remain) = buf.split_at_mut(remaining_len);
            let source = &remain[(read_offset - remaining_len)..read_offset];
            distination.copy_from_slice(source);
            read_offset = remaining_len;
        }
    }
    Ok(end_pos)
}

fn write_back_block(bin: &[u8]) -> Result<usize, (hunk::ParseError, usize)> {
    // TODO CHECKME: For better performance, maybe we should only parse hunk headers and use memcpy
    // for copying actual hunks?
    let (hunks, next_offset) = hunk::decode_hunks(bin, 0)?;
    debug!("Writeback: decoded {} hunks. Remaining {} byte(s).",
           hunks.len(),
           bin.len() - next_offset);

    let mut hunks_by_brick = HashMap::new();

    // TODO: Use Rayon's parallel map to distribute checksum calculations across processor cores.
    for boxed_hunk in hunks {
        if let BoxedHunk::BlobWal(blob_wal_hunk) = boxed_hunk {
            let BlobWalHunk { brick_name, flags, mut blobs, /* checksum, */ .. } = blob_wal_hunk;

            // TODO: Verify the checksum.

            assert_eq!(4, blobs.len());
            let encoded_pos = blobs.pop().expect("Cannot pop encoded_pos").0;
            let key = blobs.pop().expect("Cannot pop key").0;
            let value_checksum_v = blobs.pop().expect("Cannot pop value_checksum").0;
            let blob = blobs.pop().expect("Cannot pop blob");

            let mut decoder = Deserializer::new(&encoded_pos[..]);
            let pos: AllocatedPrivateHLogPosition = Deserialize::deserialize(&mut decoder).ok().unwrap();

            let mut value_checksum = [0u8; CHECKSUM_LEN];
            value_checksum.copy_from_slice(&value_checksum_v);

            let blob_single_hunk = BlobSingleHunk::new_with_checksum(blob, &flags, Some(value_checksum));
            let BinaryHunk { hunk: binary_hunk, hunk_size, .. } = blob_single_hunk.encode();

            let rec =  WriteBackRecord { hunk: binary_hunk, hunk_size, key, pos };
            let hunks = hunks_by_brick.entry(brick_name).or_insert_with(Vec::new);
            hunks.push(rec);
        } else {
            unreachable!();
        }
    }

    for (brick_name, hunks) in hunks_by_brick {
        debug!("Writeback: {}: {} hunks.", brick_name, hunks.len());
    }

    Ok(next_offset)
}
