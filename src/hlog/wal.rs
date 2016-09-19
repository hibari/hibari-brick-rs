use promising_future::{future_promise, Promise, Future};

use std::io::prelude::*;

use std::fs::File;
use std::io::{self, BufWriter, SeekFrom};

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::mpsc::{channel, Sender, SendError, Receiver};
use std::thread;

use rustc_serialize::hex::ToHex;

use hlog::hunk::{BinaryHunk, Blob, BlobWalHunk, Hunk};

// Consts / Statics

// TODO: Configurable
pub const WAL_PATH: &'static str = "/home/tatsuya/tmp/hibari_storage_wal";

lazy_static! {
    static ref WAL_WRITER: WalWriter = WalWriter::new();
}

// Thread local for client threads
thread_local!(static LOCAL_Q: Sender<Request> = WAL_WRITER.queue.lock().unwrap().clone());

// Types, Structs

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
        promise: Promise<PutBlobResult>,
    },
    Flush(Promise<FlushPosition>),
    Shutdown(Promise<bool>),
}

#[derive(Debug)]
struct BrickInfo {
    brick_name: String,
    head_seqnum: SeqNum,
    head_position: HunkOffset,
    writeback_seqnum: SeqNum,
}

#[derive(PartialEq, Debug)]
pub struct PutBlobResult {
    pub brick_name: String,
    pub storage_position: WalPosition,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub struct WalPosition {
    wal_seqnum: SeqNum,
    wal_hunk_pos: HunkOffset,
    private_seqnum: SeqNum,
    private_hunk_pos: HunkOffset,
    val_offset: ValOffset,
    pub val_len: Len,
    pub md5_string: Option<String>,
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
            let f = File::create(WAL_PATH).unwrap();
            let writer = BufWriter::new(f);
            process_requests(rx, writer);
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

    // Executed by the WAL thread
    pub fn put_value(brick_id: BrickId, key: Vec<u8>, value: Vec<u8>) -> Future<PutBlobResult> {
        let (future, prom) = future_promise();
        let req = Request::PutBlob {
            brick_id: brick_id,
            key: key,
            value: value,
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
        let mut f = try!(File::open(WAL_PATH));
        let mut pos = try!(f.seek(SeekFrom::Start(position)));
        if pos < position {
            WalWriter::flush();
            pos = try!(f.seek(SeekFrom::Start(position)));
        }
        assert_eq!(pos, position);

        let val_len = wal_position.val_len as u64;
        let mut chunk = f.take(val_len);
        let mut buf = Vec::with_capacity(val_len as usize);
        let mut size = try!(chunk.read_to_end(&mut buf));
        if size < val_len as usize {
            WalWriter::flush();
            size = try!(chunk.read_to_end(&mut buf));
        }
        assert_eq!(val_len as usize, size);

        Ok(Some(buf))
    }

    // Executed by the WAL thread
    pub fn flush() {
        let (future, prom) = future_promise();
        send(Request::Flush(prom)).unwrap();
        future.value().unwrap();
    }

    // Executed by the WAL thread
    pub fn shutdown() {
        let (future, prom) = future_promise();
        send(Request::Shutdown(prom)).unwrap();
        future.value().unwrap();
    }
}

fn send(req: Request) -> Result<(), SendError<Request>> {
    LOCAL_Q.with(|queue| queue.send(req))
}

fn process_requests(rx: Receiver<Request>, mut writer: BufWriter<File>) {

    // State
    // let mut seq_num: SeqNum = 0u32;
    let mut pos: HunkOffset = 0u64;
    let mut brick_ids: HashMap<String, BrickId> = HashMap::new();
    let mut brick_info_v: Vec<BrickInfo> = Vec::new();

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
            Request::PutBlob { brick_id, value, promise, .. } => {
                // TODO: Bound check
                let brick_info = &brick_info_v[brick_id];
                let brick_name = &brick_info.brick_name;

                if let Ok(wal_position) = do_put_blob(&mut writer, &mut pos, brick_info, value) {
                    let result = PutBlobResult {
                        brick_name: brick_name.to_string(),
                        storage_position: wal_position,
                    };
                    promise.set(result);
                } else {
                    // TODO: Need to return an error. e.g. io::Result<PubBlobResult> ?
                    let result = PutBlobResult {
                        brick_name: brick_name.to_string(),
                        storage_position: WalPosition {
                            wal_seqnum: 0,
                            wal_hunk_pos: 0,
                            private_seqnum: 0,
                            private_hunk_pos: 0,
                            val_offset: 0,
                            val_len: 0,
                            md5_string: None,
                        },
                    };
                    promise.set(result);
                }
            }
            Request::Flush(promise) => {
                writer.flush().unwrap();
                promise.set(FlushPosition { pos: pos });
            }
            Request::Shutdown(promise) => {
                writer.flush().unwrap();
                promise.set(true);
                break;  // break from the event loop.
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
               brick_info: &BrickInfo,
               value: Vec<u8>)
               -> Result<WalPosition, ()> {
    let hunk_flags = [];
    let val_len = value.len() as Len;
    let blobs = vec![Blob(value)];

    let hunk = BlobWalHunk::new(&brick_info.brick_name, blobs, &hunk_flags);
    let maybe_md5_string = hunk.md5.as_ref().map(|digest| digest[..].to_hex());

    let BinaryHunk { hunk: binary_hunk, hunk_size, blob_index, .. } = hunk.encode();
    writer.write_all(&binary_hunk[..]).unwrap();

    let wal_position = WalPosition {
        wal_seqnum: 0,
        wal_hunk_pos: *pos,
        private_seqnum: 0,
        private_hunk_pos: 0,
        val_offset: blob_index[0],
        val_len: val_len as Len,
        md5_string: maybe_md5_string,
    };

    *pos += hunk_size as HunkOffset;
    Ok(wal_position)
}
