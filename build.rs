fn main() {
    // println!("cargo:rustc-link-lib=static=rocksdb"); // Error: recompile with -fPIC
    println!("cargo:rustc-link-search=native=/usr/local/lib");
}
