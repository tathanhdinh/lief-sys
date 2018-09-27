use lief_sys;

use chrono::NaiveDateTime;
use std::{
    ffi::{CStr, CString},
    io::{self, Write},
    path,
};
use structopt::StructOpt;
use tabwriter::TabWriter;

#[derive(StructOpt)]
#[structopt(name = "pereader", about = "A simple PE reader")]
struct Args {
    #[structopt(name = "PE file", parse(from_os_str))]
    input: path::PathBuf,
}

fn main() {
    let args = Args::from_args();

    let tabbed_stdout = io::stdout();
    let mut tabbed_stdout = {
        let w = tabbed_stdout.lock();
        let w = io::BufWriter::new(w);
        TabWriter::new(w)
    };

    let raw_pe;

    let pe = {
        let input = args.input.to_string_lossy().into_owned();
        let input = CString::new(input).unwrap();

        raw_pe = unsafe { lief_sys::pe_parse(input.as_ptr()) };
        if raw_pe.is_null() {
            panic!("cannot parse PE file");
        }
        unsafe { *raw_pe }
    };

    let pe_name = unsafe { CStr::from_ptr(pe.name).to_str().unwrap() };
    writeln!(tabbed_stdout, "File:\t{}", pe_name);

    writeln!(tabbed_stdout, "\t");

    let dos_header = &pe.dos_header;
    writeln!(
        tabbed_stdout,
        "DOS header\t================="
    );
    writeln!(
        tabbed_stdout,
        "Used bytes in the last page:\t0x{:x}",
        dos_header.used_bytes_in_the_last_page
    );
    writeln!(
        tabbed_stdout,
        "File size in pages:\t0x{:x}",
        dos_header.file_size_in_pages
    );
    writeln!(
        tabbed_stdout,
        "Number of relocations:\t0x{:x}",
        dos_header.numberof_relocation
    );
    writeln!(
        tabbed_stdout,
        "Header size in paragraphs:\t0x{:x}",
        dos_header.header_size_in_paragraphs
    );
    writeln!(
        tabbed_stdout,
        "Minimum extra paragraphs:\t0x{:x}",
        dos_header.minimum_extra_paragraphs
    );
    writeln!(
        tabbed_stdout,
        "Maximum extra paragraphs:\t0x{:x}",
        dos_header.maximum_extra_paragraphs
    );
    writeln!(
        tabbed_stdout,
        "Initial relative stack segment:\t0x{:x}",
        dos_header.initial_relative_ss
    );
    writeln!(
        tabbed_stdout,
        "Initial stack pointer:\t0x{:x}",
        dos_header.initial_sp
    );
    writeln!(tabbed_stdout, "Checksum:\t0x{:x}", dos_header.checksum);
    writeln!(
        tabbed_stdout,
        "Initial relative code segment:\t0x{:x}",
        dos_header.initial_relative_cs
    );
    writeln!(tabbed_stdout, "Checksum:\t0x{:x}", dos_header.checksum);
    writeln!(
        tabbed_stdout,
        "Address of relocation table:\t0x{:x}",
        dos_header.addressof_relocation_table
    );
    writeln!(
        tabbed_stdout,
        "Overlay number:\t0x{:x}",
        dos_header.overlay_number
    );
    writeln!(tabbed_stdout, "OEM id:\t0x{:x}", dos_header.oem_id);
    writeln!(tabbed_stdout, "OEM info:\t0x{:x}", dos_header.oem_info);
    writeln!(
        tabbed_stdout,
        "Address of PE header:\t0x{:x}",
        dos_header.addressof_new_exeheader
    );

    writeln!(tabbed_stdout, "\t");

    let pe_header = &pe.header;
    writeln!(
        tabbed_stdout,
        "PE header\t================="
    );
    let machine_type = {
        let machine = pe_header.machine;
        let machine = unsafe { lief_sys::MACHINE_TYPES_to_string(machine) };
        unsafe { CStr::from_ptr(machine).to_str().unwrap() }
    };
    writeln!(tabbed_stdout, "Machine:\t{}", machine_type);
    writeln!(
        tabbed_stdout,
        "Number of sections:\t{}",
        pe_header.numberof_sections
    );
    writeln!(
        tabbed_stdout,
        "Timestamp:\t{}",
        NaiveDateTime::from_timestamp(pe_header.time_date_stamp as i64, 0)
    );
    writeln!(
        tabbed_stdout,
        "Pointer to symbol table:\t0x{:x}",
        pe_header.pointerto_symbol_table
    );
    writeln!(
        tabbed_stdout,
        "Number of symbols:\t{}",
        pe_header.numberof_symbols
    );
    writeln!(
        tabbed_stdout,
        "Sizeof optional header:\t0x{:x}",
        pe_header.sizeof_optional_header
    );
    writeln!(
        tabbed_stdout,
        "Characteristics:\t0x{:x}",
        pe_header.characteristics
    );

    writeln!(tabbed_stdout, "\t");

    let optional_header = pe.optional_header;
    writeln!(
        tabbed_stdout,
        "Optional header\t================="
    );
    let magic = {
        let magic = unsafe { lief_sys::PE_TYPES_to_string(optional_header.magic) };
        unsafe { CStr::from_ptr(magic).to_str().unwrap() }
    };
    writeln!(tabbed_stdout, "Magic:\t{}", magic);
    writeln!(
        tabbed_stdout,
        "Major linker version:\t0x{:x}",
        optional_header.major_linker_version
    );
    writeln!(
        tabbed_stdout,
        "Minor linker version:\t0x{:x}",
        optional_header.minor_linker_version
    );
    writeln!(
        tabbed_stdout,
        "Size ofcode:\t0x{:x}",
        optional_header.sizeof_code
    );
    writeln!(
        tabbed_stdout,
        "Size of initialized data:\t0x{:x}",
        optional_header.sizeof_initialized_data
    );
    writeln!(
        tabbed_stdout,
        "Size of uninitialized data:\t0x{:x}",
        optional_header.sizeof_uninitialized_data
    );
    writeln!(
        tabbed_stdout,
        "Address of entrypoint:\t0x{:x}",
        optional_header.addressof_entrypoint
    );
    writeln!(
        tabbed_stdout,
        "Base of code:\t0x{:x}",
        optional_header.baseof_code
    );
    writeln!(
        tabbed_stdout,
        "Base of data:\t0x{:x}",
        optional_header.baseof_data
    );
    writeln!(
        tabbed_stdout,
        "Image base:\t0x{:x}",
        optional_header.imagebase
    );
    writeln!(
        tabbed_stdout,
        "Section alignment:\t0x{:x}",
        optional_header.section_alignment
    );
    writeln!(
        tabbed_stdout,
        "File alignment:\t0x{:x}",
        optional_header.file_alignment
    );
    writeln!(
        tabbed_stdout,
        "Major operating system version:\t0x{:x}",
        optional_header.major_operating_system_version
    );
    writeln!(
        tabbed_stdout,
        "Minor operating system version:\t0x{:x}",
        optional_header.minor_operating_system_version
    );
    writeln!(
        tabbed_stdout,
        "Major image version:\t0x{:x}",
        optional_header.major_image_version
    );
    writeln!(
        tabbed_stdout,
        "Minor image version:\t0x{:x}",
        optional_header.minor_image_version
    );
    writeln!(
        tabbed_stdout,
        "Major subsystem version:\t0x{:x}",
        optional_header.major_subsystem_version
    );
    writeln!(
        tabbed_stdout,
        "Minor subsystem version:\t0x{:x}",
        optional_header.minor_subsystem_version
    );
    writeln!(
        tabbed_stdout,
        "Win32 version value:\t0x{:x}",
        optional_header.win32_version_value
    );
    writeln!(
        tabbed_stdout,
        "Size of image:\t0x{:x}",
        optional_header.sizeof_image
    );
    writeln!(
        tabbed_stdout,
        "Size of headers:\t0x{:x}",
        optional_header.sizeof_headers
    );
    writeln!(tabbed_stdout, "Checksum:\t0x{:x}", optional_header.checksum);
    let subsystem = {
        let subsystem = unsafe { lief_sys::SUBSYSTEM_to_string(optional_header.subsystem) };
        unsafe { CStr::from_ptr(subsystem).to_str().unwrap() }
    };
    writeln!(tabbed_stdout, "Subsystem:\t{}", subsystem);
    writeln!(
        tabbed_stdout,
        "DLL characteristics:\t0x{:x}",
        optional_header.dll_characteristics
    );
    writeln!(
        tabbed_stdout,
        "Size of stack reserve:\t0x{:x}",
        optional_header.sizeof_stack_reserve
    );
    writeln!(
        tabbed_stdout,
        "Size of stack commit:\t0x{:x}",
        optional_header.sizeof_stack_commit
    );
    writeln!(
        tabbed_stdout,
        "Size of heap reserve:\t0x{:x}",
        optional_header.sizeof_heap_reserve
    );
    writeln!(
        tabbed_stdout,
        "Size of heap commit:\t0x{:x}",
        optional_header.sizeof_heap_commit
    );
    writeln!(
        tabbed_stdout,
        "Loader flags:\t0x{:x}",
        optional_header.loader_flags
    );
    writeln!(
        tabbed_stdout,
        "Number of rva and size:\t0x{:x}",
        optional_header.numberof_rva_and_size
    );

    unsafe { lief_sys::pe_binary_destroy(raw_pe) };

    tabbed_stdout.flush().unwrap();
}
