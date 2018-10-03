use std::ffi::{CStr, CString};

mod gen;

use self::lief::*;
use crate::gen as lief;

pub fn pe_parse<'a>(file: &str) -> Option<&'a mut Pe_Binary_t> {
    let file = CString::new(file.clone());
    if let Ok(file) = file {
        unsafe { lief::pe_parse(file.as_ptr()).as_mut() }
    } else {
        None
    }
}

pub fn pe_destroy(pe: &mut Pe_Binary_t) {
    unsafe { lief::pe_binary_destroy(pe) }
}

pub fn pe_types_to_str(t: LIEF_PE_PE_TYPES) -> Option<&'static str> {
    unsafe { CStr::from_ptr(lief::PE_TYPES_to_string(t)) }
        .to_str()
        .ok()
}

pub fn pe_machine_types_to_str(t: LIEF_PE_MACHINE_TYPES) -> Option<&'static str> {
    unsafe { CStr::from_ptr(lief::MACHINE_TYPES_to_string(t)) }
        .to_str()
        .ok()
}
