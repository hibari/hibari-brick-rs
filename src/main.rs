#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

extern crate hibari_brick_rs as brick;

use std::thread;
use std::sync::Arc;

const NUM_THREADS: u32 = 50;
const NUM_KEYS_PER_THREAD: u32 = 10_000;

fn main() {
    let brick_name = "brick1";
    let brick_id = brick::add_brick(brick_name);

    let put_op = |brick_id: brick::BrickId, key_str: &str, key: &[u8], value: &[u8]| {
        brick::put(brick_id, key.to_vec(), value.to_vec())
            .expect(&format!("Failed to put a key {}", key_str));
    };

    let get_op = |brick_id: brick::BrickId, key_str: &str, key: &[u8], value: &[u8]| {
        let val = brick::get(brick_id, key).expect(&format!("Failed to get a key {}", key_str));
        assert_eq!(value.to_vec(), val.unwrap());
    };

    do_ops(brick_id, NUM_THREADS, NUM_KEYS_PER_THREAD, "put", put_op);
    do_ops(brick_id, NUM_THREADS, NUM_KEYS_PER_THREAD, "get", get_op);

    brick::shutdown();

    println!("Done!");
}

fn do_ops<F>(brick_id: brick::BrickId,
             num_threads: u32,
             num_keys_per_thread: u32,
             op_name: &str,
             op: F)
    where F: Fn(brick::BrickId, &str, &[u8], &[u8]) + Send + Sync + 'static
{
    let op = Arc::new(op);

    let handles: Vec<_> = (0..num_threads)
        .into_iter()
        .map(|n| {
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

                println!("Thread {} ended. (Performed {} {} operations.", n, count, my_op_name);

                assert_eq!(num_keys_per_thread, count);
            })
        })
        .collect();

    for (i, h) in handles.into_iter().enumerate() {
        h.join().expect(&format!("Thread {} failed", i));
    }
}
