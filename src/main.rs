#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

extern crate hibari_brick_rs;

use hibari_brick_rs::{add_brick, get, put, shutdown, BrickId};

use std::io;
use std::thread;

const NUM_THREADS: u32 = 50;
const NUM_KEYS_PER_THREAD: u32 = 10_000;

fn main() {
    let brick_name = "brick1";
    let brick_id = add_brick(brick_name);

    put_objects(brick_id, NUM_THREADS, NUM_KEYS_PER_THREAD).unwrap();
    get_objects(brick_id, NUM_THREADS, NUM_KEYS_PER_THREAD).unwrap();

    shutdown();

    println!("Done!");
}

fn put_objects(brick_id: BrickId, num_threads: u32, num_keys_per_thread: u32) -> io::Result<()> {
    let handles: Vec<_> = (0..num_threads)
        .into_iter()
        .map(|n| {
            thread::spawn(move || {
                println!("Thread {} started for put ops.", n);

                let start = n * num_keys_per_thread;
                let end = start + num_keys_per_thread;
                let mut key;
                let mut value;

                for i in start..end {
                    key = format!("key{:010}", i);
                    value = format!("value{:010}", i);
                    put(brick_id, key.as_bytes().to_vec(), value.as_bytes().to_vec())
                        .expect(&format!("Failed to put a key {}", key));
                }

                println!("Thread {} ended.", n);
            })
        })
        .collect();

    for (i, h) in handles.into_iter().enumerate() {
        h.join().expect(&format!("Thread {} failed", i));
    }

    Ok(())
}

fn get_objects(brick_id: BrickId, num_threads: u32, num_keys_per_thread: u32) -> io::Result<()> {
    let handles: Vec<_> = (0..num_threads)
        .into_iter()
        .map(|n| {
            thread::spawn(move || {
                println!("Thread {} started for get ops.", n);

                let start = n * num_keys_per_thread;
                let end = start + num_keys_per_thread;
                let mut key;
                let mut value;

                for i in start..end {
                    key = format!("key{:010}", i);
                    value = format!("value{:010}", i);
                    let val = get(brick_id, key.as_bytes())
                        .expect(&format!("Failed to get a key {}", key));
                    assert_eq!(value.as_bytes().to_vec(), val.unwrap());
                }

                println!("Thread {} ended.", n);
            })
        })
        .collect();

    for (i, h) in handles.into_iter().enumerate() {
        h.join().expect(&format!("Thread {} failed", i));
    }

    Ok(())
}
