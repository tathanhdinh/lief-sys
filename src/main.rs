extern crate lief_sys;

use lief_sys::*;

#[allow(unused_imports)]
use std::ffi::{CStr, CString};

fn main() {
    // unimplemented!();
    // #[link(name="LIEF", kind="static")]
    let filename = CString::new("/bin/ls").unwrap().as_ptr();
    let binary = unsafe { elf_parse(filename) };
    let _= unsafe { elf_binary_destroy(binary) };
}
