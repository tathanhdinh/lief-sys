use bindgen;
use std::{env, path};

const LIEF_SDK_DIR: &'static str = "lief-sdk";
const LIEF_C_LIB: &'static str = "LIEF";

fn generate_binding(out_dir_path: &path::Path, lief_c_path: &path::Path) {
    let lief_c_include_path = {
        let path = lief_c_path.join("include");
        if !path.exists() {
            panic!("LIEF C include path not found")
        }
        path
    };

    let lief_c_header = {
        let path = lief_c_include_path.join("LIEF").join("LIEF.h");
        if !path.exists() {
            panic!("LIEF C header not found")
        }
        path
    };

    let lief_binder = bindgen::Builder::default()
        .header(lief_c_header.to_string_lossy())
        .clang_arg(format!("-I{}", lief_c_include_path.to_string_lossy()))
        .prepend_enum_name(false)
        .rustified_enum("*")
        .derive_partialord(true)
        .no_partialeq(
            "max_align_t|__fsid_t|imaxdiv_t|\
            __crt_locale_data_public|__crt_locale_pointers|__crt_locale_pointers|_Mbstatet|_Lldiv_t|__crt_locale_data|__crt_multibyte_data|\
            Macho_Header_t|Macho_Command_t|Macho_Symbol_t|Macho_Section_t|Macho_Segment_t|Macho_Binary_t|\
            Pe_DosHeader_t|Pe_Header_t|Pe_OptionalHeader_t|Pe_DataDirectory_t|\
            Pe_Section_t|Pe_ImportEntry_t|Pe_Import_t|Pe_Binary_t|\
            Elf_Section_t|Elf_Segment_t|Elf_Header_t|Elf_DynamicEntry_t|Elf_DynamicEntry_Library_t|\
            Elf_DynamicEntry_SharedObject_t|Elf_DynamicEntry_Array_t|Elf_DynamicEntry_Rpath_t|\
            Elf_DynamicEntry_RunPath_t|Elf_DynamicEntry_Flags_t|Elf_Symbol_t|Elf_Binary_t")
        .generate()
        .expect("Unable to generate LIEF bindings");

    lief_binder
        .write_to_file(out_dir_path.join("bindings.rs"))
        .expect("Unable to export LIEF bindings");
}

fn main() {
    let out_dir_path = {
        let out_dir = crate::env::var("OUT_DIR")
            .expect("Unable to get value of OUT_DIR environment variable");
        path::PathBuf::from(out_dir)
    };

    let lief_sdk_path = {
        let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let path = path::PathBuf::from(&crate_dir).join(LIEF_SDK_DIR);
        if !path.exists() {
            panic!("LIEF sdk directory not found");
        }
        path
    };

    println!("cargo:rerun-if-changed={}", LIEF_SDK_DIR);

    generate_binding(&out_dir_path, &lief_sdk_path);

    let lief_lib_path = {
        let path = lief_sdk_path.join("lib");
        if !path.exists() {
            panic!("LIEF lib path not found")
        }
        path
    };

    println!(
        "cargo:rustc-link-search={}={}",
        "native",
        lief_lib_path.to_string_lossy()
    );

    println!("cargo:rustc-link-lib={}={}", "static", LIEF_C_LIB);

    #[cfg(target_family = "unix")]
    println!("cargo:rustc-link-lib=dylib=stdc++");
}
