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
use rand::{self, Rng};
use timer;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::sync::mpsc::{channel, Sender, SendError, Receiver};
use std::thread;

// TODO: Configurable
pub const PRIVATE_BLOB_PATH: &'static str = "/tmp/hibari-brick-test-data-blob";
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
    // FullWriteBack(Promise<bool>),
    Shutdown(Promise<bool>),
}

pub struct WriteBack {
    queue: Mutex<Sender<Request>>,
}

impl WriteBack {
    fn new() -> Self {
        let (tx, rx) = channel();

        // TODO: Give a name to the threads. (Hint: Use thread builder)
        thread::spawn(move || handle_requests(rx));
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

// Drop will never called because it is the WriteBack is bound to static? 
impl Drop for WriteBack {
    fn drop(&mut self) {
        WriteBack::shutdown();
    }
}

fn send(req: Request) -> Result<(), SendError<Request>> {
    LOCAL_Q.with(|queue| queue.send(req))
}

fn handle_requests(rx: Receiver<Request>) {
    // State
    let _writer_back_scheduler = start_write_back_scheduler();
    let mut rng = rand::thread_rng();

    loop {
        match rx.recv().unwrap() {
            Request::Poke => (),
            Request::WriteBack => {
                println!("WriteBack started"); // TODO: Use env logger
                IS_WRITE_BACK_RUNNING.store(true, Ordering::Relaxed);
                let secs = rng.gen_range(1, 4);
                let dur = ::std::time::Duration::from_secs(secs);
                thread::sleep(dur);
                IS_WRITE_BACK_RUNNING.store(false, Ordering::Relaxed);
                println!("WriteBack finished. {} secs", secs)
            }
            Request::Shutdown(promise) => {
                promise.set(true);
                break; // break from the event loop.
            }
        }
    }
}

fn start_write_back_scheduler() -> (timer::Timer, timer::Guard) {
    let timer = timer::Timer::new();
    // holding the guard seems required, otherwise timer will never go off.
    let guard = timer.schedule_repeating(
        chrono::Duration::seconds(WRITE_BACK_INTERVAL_SECS),
        || if !IS_WRITE_BACK_RUNNING.load(Ordering::Relaxed) {
                let _ignore = send(Request::WriteBack); // avoid unwrapping here.
        });
    (timer, guard)
}
