# lief-sys

This is a low-level binding for Quarkslab's [LIEF](https://lief.quarkslab.com/).

## Example

```
use lief_sys;

let raw_pe;
let pe = {
    let input = CString::new("notepad.exe).unwrap();
    raw_pe = unsafe { lief_sys::pe_parse(input.as_ptr()) };
    if raw_pe.is_null() {
        panic!("unable to parse PE file");
    }
    unsafe { *raw_pe }
};

let dos_header = &pe.dos_header;
println!("Address of PE header:\t0x{:x}", dos_header.addressof_new_exeheader);

unsafe { lief_sys::pe_binary_destroy(raw_pe) };
```

There are [more](examples/).

## Installation

We needs to create a folder `lief-sdk` in the crate's root, then copy the corresponding LIEF's [SDK](https://lief.quarkslab.com/#download). For instance

```
wget https://github.com/lief-project/LIEF/releases/download/0.9.0/LIEF-0.9.0-Linux.tar.gz
mkdir lief-sdk
tar xzf LIEF-0.9.0-Linux.tar.gz -C lief-sdk --strip-components=1
cargo build
```

The binding is tested on Windows and Linux (I hope it works also on OSX, but I've no machine to check).

## Issues

Many thanks for any help, there are already opened [issues](https://github.com/tathanhdinh/lief-sys/issues).