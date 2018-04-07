// ----------------------------------------------------------------------
//  Copyright (c) 2016-2018 Hibari developers. All rights reserved.
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

#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

extern crate env_logger;
extern crate hibari_brick_rs as brick;

use std::thread;
use std::sync::Arc;

const NUM_THREADS: u32 = 50;
const NUM_KEYS_PER_THREAD: u32 = 50_000;
const VALUE_SIZE: usize = 1024;

fn main() {
    env_logger::init();

    let brick_names = ["brick1", "brick2", "brick3", "brick4"];
    let mut brick_ids = [0; 4];
    for (i, brick_name) in brick_names.iter().enumerate() {
        brick_ids[i] = brick::add_brick(brick_name);
    }

    let put_op = |brick_id: brick::BrickId, key_str: &str, key: &[u8], value: &[u8]| {
        let mut large_value = vec![0; VALUE_SIZE];
        large_value[..value.len()].copy_from_slice(value);

        brick::put(brick_id, key, large_value).expect(&format!("Failed to put a key {}", key_str));
    };

    let get_op = |brick_id: brick::BrickId, key_str: &str, key: &[u8], value: &[u8]| {
        let val = brick::get(brick_id, key)
            .expect(&format!("Failed to get a key {}", key_str))
            .expect(&format!("Value for key {} is None", key_str));
        assert_eq!(VALUE_SIZE, val.len());
        assert_eq!(value, &val[..value.len()]);
    };

    do_ops(
        &brick_ids[..],
        NUM_THREADS,
        NUM_KEYS_PER_THREAD,
        "put",
        put_op,
    );
    do_ops(
        &brick_ids[..],
        NUM_THREADS,
        NUM_KEYS_PER_THREAD,
        "get",
        get_op,
    );

    brick::shutdown();

    println!("Done!");
}

fn do_ops<F>(
    brick_ids: &[brick::BrickId],
    num_threads: u32,
    num_keys_per_thread: u32,
    op_name: &str,
    op: F,
) where
    F: Fn(brick::BrickId, &str, &[u8], &[u8]) + Send + Sync + 'static,
{
    let num_bricks = brick_ids.len();
    let op = Arc::new(op);

    let handles: Vec<_> = (0..num_threads)
        .into_iter()
        .map(|n| {
            let brick_id = brick_ids[n as usize % num_bricks];
            let my_op = op.clone();
            let my_op_name = op_name.to_owned();

            thread::spawn(move || {
                println!("Thread {} started for {} operations.", n, my_op_name);

                let start = n * num_keys_per_thread;
                let end = start + num_keys_per_thread;
                let mut key;
                let mut value;
                let mut count = 0;

                for i in start..end {
                    key = format!("key{:010}", i);
                    value = format!("value{:010}", i);
                    my_op(brick_id, &key, key.as_bytes(), value.as_bytes());
                    count += 1;
                }

                println!(
                    "Thread {} ended. (Performed {} {} operations.",
                    n, count, my_op_name
                );

                assert_eq!(num_keys_per_thread, count);
            })
        })
        .collect();

    for (i, h) in handles.into_iter().enumerate() {
        h.join().expect(&format!("Thread {} failed", i));
    }
}
