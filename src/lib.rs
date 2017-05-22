extern crate libc;

#[allow(unused_imports)]
use libc::{c_void, c_char, c_int};

#[allow(unused_imports)]
use std::ffi::{CStr, CString};


// #[warn(non_camel_case_types)]
#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SECTION_TYPES {
    SHT_NULL               = 0,
    SHT_PROGBITS           = 1,
    SHT_SYMTAB             = 2,
    SHT_STRTAB             = 3,
    SHT_RELA               = 4,
    SHT_HASH               = 5,
    SHT_DYNAMIC            = 6,
    SHT_NOTE               = 7,
    SHT_NOBITS             = 8,
    SHT_REL                = 9,
    SHT_SHLIB              = 10,
    SHT_DYNSYM             = 11,
    SHT_INIT_ARRAY         = 14,
    SHT_FINI_ARRAY         = 15,
    SHT_PREINIT_ARRAY      = 16,
    SHT_GROUP              = 17,
    SHT_SYMTAB_SHNDX       = 18,
    SHT_LOOS               = 1610612736,
    SHT_GNU_ATTRIBUTES     = 1879048181,
    SHT_GNU_HASH           = 1879048182,
    SHT_GNU_verdef         = 1879048189,
    SHT_GNU_verneed        = 1879048190,
    SHT_GNU_versym         = 1879048191,
    SHT_LOPROC             = 1879048192,
    SHT_ARM_EXIDX          = 1879048193,
    SHT_ARM_PREEMPTMAP     = 1879048194,
    SHT_ARM_ATTRIBUTES     = 1879048195,
    SHT_ARM_DEBUGOVERLAY   = 1879048196,
    SHT_ARM_OVERLAYSECTION = 1879048197,
    SHT_MIPS_REGINFO       = 1879048198,
    SHT_MIPS_OPTIONS       = 1879048205,
    SHT_MIPS_ABIFLAGS      = 1879048234,
    SHT_HIPROC             = 2147483647,
    SHT_LOUSER             = 2147483648,
    SHT_HIUSER             = 4294967295,
}


#[repr(C)]
#[derive(Debug, Copy)]
pub struct Elf_Section_t {
    pub name: *const c_char,
    pub flags: u32,
    pub type_: SECTION_TYPES,
    pub virtual_address: u64,
    pub offset: u64,
    pub original_size: u64,
    pub link: u32,
    pub info: u32,
    pub alignment: u64,
    pub entry_size: u64,
    pub size: u64,
    pub content: *mut u8,
    pub entropy: f64,
}


impl Clone for Elf_Section_t {
    // fn clone(&self) -> Self { *self }
    fn clone(&self) -> Elf_Section_t { *self }
}


#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ELF_CLASS { ELFCLASSNONE = 0, ELFCLASS32 = 1, ELFCLASS64 = 2, }


#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum E_TYPE {
    ET_NONE   = 0,
    ET_REL    = 1,
    ET_EXEC   = 2,
    ET_DYN    = 3,
    ET_CORE   = 4,
    ET_LOPROC = 65280,
    ET_HIPROC = 65535,
}


#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ARCH {
    EM_NONE          = 0,
    EM_M32           = 1,
    EM_SPARC         = 2,
    EM_386           = 3,
    EM_68K           = 4,
    EM_88K           = 5,
    EM_IAMCU         = 6,
    EM_860           = 7,
    EM_MIPS          = 8,
    EM_S370          = 9,
    EM_MIPS_RS3_LE   = 10,
    EM_PARISC        = 15,
    EM_VPP500        = 17,
    EM_SPARC32PLUS   = 18,
    EM_960           = 19,
    EM_PPC           = 20,
    EM_PPC64         = 21,
    EM_S390          = 22,
    EM_SPU           = 23,
    EM_V800          = 36,
    EM_FR20          = 37,
    EM_RH32          = 38,
    EM_RCE           = 39,
    EM_ARM           = 40,
    EM_ALPHA         = 41,
    EM_SH            = 42,
    EM_SPARCV9       = 43,
    EM_TRICORE       = 44,
    EM_ARC           = 45,
    EM_H8_300        = 46,
    EM_H8_300H       = 47,
    EM_H8S           = 48,
    EM_H8_500        = 49,
    EM_IA_64         = 50,
    EM_MIPS_X        = 51,
    EM_COLDFIRE      = 52,
    EM_68HC12        = 53,
    EM_MMA           = 54,
    EM_PCP           = 55,
    EM_NCPU          = 56,
    EM_NDR1          = 57,
    EM_STARCORE      = 58,
    EM_ME16          = 59,
    EM_ST100         = 60,
    EM_TINYJ         = 61,
    EM_X86_64        = 62,
    EM_PDSP          = 63,
    EM_PDP10         = 64,
    EM_PDP11         = 65,
    EM_FX66          = 66,
    EM_ST9PLUS       = 67,
    EM_ST7           = 68,
    EM_68HC16        = 69,
    EM_68HC11        = 70,
    EM_68HC08        = 71,
    EM_68HC05        = 72,
    EM_SVX           = 73,
    EM_ST19          = 74,
    EM_VAX           = 75,
    EM_CRIS          = 76,
    EM_JAVELIN       = 77,
    EM_FIREPATH      = 78,
    EM_ZSP           = 79,
    EM_MMIX          = 80,
    EM_HUANY         = 81,
    EM_PRISM         = 82,
    EM_AVR           = 83,
    EM_FR30          = 84,
    EM_D10V          = 85,
    EM_D30V          = 86,
    EM_V850          = 87,
    EM_M32R          = 88,
    EM_MN10300       = 89,
    EM_MN10200       = 90,
    EM_PJ            = 91,
    EM_OPENRISC      = 92,
    EM_ARC_COMPACT   = 93,
    EM_XTENSA        = 94,
    EM_VIDEOCORE     = 95,
    EM_TMM_GPP       = 96,
    EM_NS32K         = 97,
    EM_TPC           = 98,
    EM_SNP1K         = 99,
    EM_ST200         = 100,
    EM_IP2K          = 101,
    EM_MAX           = 102,
    EM_CR            = 103,
    EM_F2MC16        = 104,
    EM_MSP430        = 105,
    EM_BLACKFIN      = 106,
    EM_SE_C33        = 107,
    EM_SEP           = 108,
    EM_ARCA          = 109,
    EM_UNICORE       = 110,
    EM_EXCESS        = 111,
    EM_DXP           = 112,
    EM_ALTERA_NIOS2  = 113,
    EM_CRX           = 114,
    EM_XGATE         = 115,
    EM_C166          = 116,
    EM_M16C          = 117,
    EM_DSPIC30F      = 118,
    EM_CE            = 119,
    EM_M32C          = 120,
    EM_TSK3000       = 131,
    EM_RS08          = 132,
    EM_SHARC         = 133,
    EM_ECOG2         = 134,
    EM_SCORE7        = 135,
    EM_DSP24         = 136,
    EM_VIDEOCORE3    = 137,
    EM_LATTICEMICO32 = 138,
    EM_SE_C17        = 139,
    EM_TI_C6000      = 140,
    EM_TI_C2000      = 141,
    EM_TI_C5500      = 142,
    EM_MMDSP_PLUS    = 160,
    EM_CYPRESS_M8C   = 161,
    EM_R32C          = 162,
    EM_TRIMEDIA      = 163,
    EM_HEXAGON       = 164,
    EM_8051          = 165,
    EM_STXP7X        = 166,
    EM_NDS32         = 167,
    EM_ECOG1         = 168,
    EM_MAXQ30        = 169,
    EM_XIMO16        = 170,
    EM_MANIK         = 171,
    EM_CRAYNV2       = 172,
    EM_RX            = 173,
    EM_METAG         = 174,
    EM_MCST_ELBRUS   = 175,
    EM_ECOG16        = 176,
    EM_CR16          = 177,
    EM_ETPU          = 178,
    EM_SLE9X         = 179,
    EM_L10M          = 180,
    EM_K10M          = 181,
    EM_AARCH64       = 183,
    EM_AVR32         = 185,
    EM_STM8          = 186,
    EM_TILE64        = 187,
    EM_TILEPRO       = 188,
    EM_CUDA          = 190,
    EM_TILEGX        = 191,
    EM_CLOUDSHIELD   = 192,
    EM_COREA_1ST     = 193,
    EM_COREA_2ND     = 194,
    EM_ARC_COMPACT2  = 195,
    EM_OPEN8         = 196,
    EM_RL78          = 197,
    EM_VIDEOCORE5    = 198,
    EM_78KOR         = 199,
    EM_56800EX       = 200,
    EM_BA1           = 201,
    EM_BA2           = 202,
    EM_XCORE         = 203,
    EM_MCHP_PIC      = 204,
    EM_INTEL205      = 205,
    EM_INTEL206      = 206,
    EM_INTEL207      = 207,
    EM_INTEL208      = 208,
    EM_INTEL209      = 209,
    EM_KM32          = 210,
    EM_KMX32         = 211,
    EM_KMX16         = 212,
    EM_KMX8          = 213,
    EM_KVARC         = 214,
    EM_CDP           = 215,
    EM_COGE          = 216,
    EM_COOL          = 217,
    EM_NORC          = 218,
    EM_CSR_KALIMBA   = 219,
    EM_AMDGPU        = 224,
}


#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum VERSION { EV_NONE = 0, EV_CURRENT = 1, }


#[repr(C)]
#[derive(Debug, Copy)]
pub struct Elf_Header_t {
    pub identity: [u8; 16usize],
    pub file_type: E_TYPE,
    pub machine_type: ARCH,
    pub object_file_version: VERSION,
    pub entrypoint: u64,
    pub program_headers_offset: u64,
    pub section_headers_offset: u64,
    pub processor_flags: u32,
    pub header_size: u32,
    pub program_header_size: u32,
    pub numberof_segments: u32,
    pub sizeof_section_header: u32,
    pub numberof_sections: u32,
    pub name_string_table_idx: u32,
}


impl Clone for Elf_Header_t {
    fn clone(&self) -> Elf_Header_t { *self }
}


#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SEGMENT_TYPES {
    PT_NULL          = 0,
    PT_LOAD          = 1,
    PT_DYNAMIC       = 2,
    PT_INTERP        = 3,
    PT_NOTE          = 4,
    PT_SHLIB         = 5,
    PT_PHDR          = 6,
    PT_TLS           = 7,
    PT_LOOS          = 1610612736,
    PT_HIOS          = 1879048191,
    PT_LOPROC        = 1879048192,
    PT_HIPROC        = 2147483647,
    PT_GNU_EH_FRAME  = 1685382480,
    PT_SUNW_UNWIND   = 1684333904,
    PT_GNU_STACK     = 1685382481,
    PT_GNU_RELRO     = 1685382482,
    PT_ARM_EXIDX     = 1879048193,
    PT_MIPS_OPTIONS  = 1879048194,
    PT_MIPS_ABIFLAGS = 1879048195,
}


#[repr(C)]
#[derive(Debug, Copy)]
pub struct Elf_Segment_t {
    pub type_: SEGMENT_TYPES,
    pub flags: u32,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub offset: u64,
    pub alignment: u64,
    pub size: u64,
    pub content: *mut u8,
}


impl Clone for Elf_Segment_t {
    fn clone(&self) -> Self { *self }
}


#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum DYNAMIC_TAGS {
    DT_NULL                       = 0,
    DT_NEEDED                     = 1,
    DT_PLTRELSZ                   = 2,
    DT_PLTGOT                     = 3,
    DT_HASH                       = 4,
    DT_STRTAB                     = 5,
    DT_SYMTAB                     = 6,
    DT_RELA                       = 7,
    DT_RELASZ                     = 8,
    DT_RELAENT                    = 9,
    DT_STRSZ                      = 10,
    DT_SYMENT                     = 11,
    DT_INIT                       = 12,
    DT_FINI                       = 13,
    DT_SONAME                     = 14,
    DT_RPATH                      = 15,
    DT_SYMBOLIC                   = 16,
    DT_REL                        = 17,
    DT_RELSZ                      = 18,
    DT_RELENT                     = 19,
    DT_PLTREL                     = 20,
    DT_DEBUG                      = 21,
    DT_TEXTREL                    = 22,
    DT_JMPREL                     = 23,
    DT_BIND_NOW                   = 24,
    DT_INIT_ARRAY                 = 25,
    DT_FINI_ARRAY                 = 26,
    DT_INIT_ARRAYSZ               = 27,
    DT_FINI_ARRAYSZ               = 28,
    DT_RUNPATH                    = 29,
    DT_FLAGS                      = 30,
    DT_ENCODING                   = 32,
    DT_PREINIT_ARRAYSZ            = 33,
    DT_LOOS                       = 1610612736,
    DT_HIOS                       = 1879048191,
    DT_LOPROC                     = 1879048192,
    DT_HIPROC                     = 2147483647,
    DT_GNU_HASH                   = 1879047925,
    DT_RELACOUNT                  = 1879048185,
    DT_RELCOUNT                   = 1879048186,
    DT_FLAGS_1                    = 1879048187,
    DT_VERSYM                     = 1879048176,
    DT_VERDEF                     = 1879048188,
    DT_VERDEFNUM                  = 1879048189,
    DT_VERNEED                    = 1879048190,
    DT_MIPS_RLD_VERSION           = 1879048193,
    DT_MIPS_TIME_STAMP            = 1879048194,
    DT_MIPS_ICHECKSUM             = 1879048195,
    DT_MIPS_IVERSION              = 1879048196,
    DT_MIPS_FLAGS                 = 1879048197,
    DT_MIPS_BASE_ADDRESS          = 1879048198,
    DT_MIPS_MSYM                  = 1879048199,
    DT_MIPS_CONFLICT              = 1879048200,
    DT_MIPS_LIBLIST               = 1879048201,
    DT_MIPS_LOCAL_GOTNO           = 1879048202,
    DT_MIPS_CONFLICTNO            = 1879048203,
    DT_MIPS_LIBLISTNO             = 1879048208,
    DT_MIPS_SYMTABNO              = 1879048209,
    DT_MIPS_UNREFEXTNO            = 1879048210,
    DT_MIPS_GOTSYM                = 1879048211,
    DT_MIPS_HIPAGENO              = 1879048212,
    DT_MIPS_RLD_MAP               = 1879048214,
    DT_MIPS_DELTA_CLASS           = 1879048215,
    DT_MIPS_DELTA_CLASS_NO        = 1879048216,
    DT_MIPS_DELTA_INSTANCE        = 1879048217,
    DT_MIPS_DELTA_INSTANCE_NO     = 1879048218,
    DT_MIPS_DELTA_RELOC           = 1879048219,
    DT_MIPS_DELTA_RELOC_NO        = 1879048220,
    DT_MIPS_DELTA_SYM             = 1879048221,
    DT_MIPS_DELTA_SYM_NO          = 1879048222,
    DT_MIPS_DELTA_CLASSSYM        = 1879048224,
    DT_MIPS_DELTA_CLASSSYM_NO     = 1879048225,
    DT_MIPS_CXX_FLAGS             = 1879048226,
    DT_MIPS_PIXIE_INIT            = 1879048227,
    DT_MIPS_SYMBOL_LIB            = 1879048228,
    DT_MIPS_LOCALPAGE_GOTIDX      = 1879048229,
    DT_MIPS_LOCAL_GOTIDX          = 1879048230,
    DT_MIPS_HIDDEN_GOTIDX         = 1879048231,
    DT_MIPS_PROTECTED_GOTIDX      = 1879048232,
    DT_MIPS_OPTIONS               = 1879048233,
    DT_MIPS_INTERFACE             = 1879048234,
    DT_MIPS_DYNSTR_ALIGN          = 1879048235,
    DT_MIPS_INTERFACE_SIZE        = 1879048236,
    DT_MIPS_RLD_TEXT_RESOLVE_ADDR = 1879048237,
    DT_MIPS_PERF_SUFFIX           = 1879048238,
    DT_MIPS_COMPACT_SIZE          = 1879048239,
    DT_MIPS_GP_VALUE              = 1879048240,
    DT_MIPS_AUX_DYNAMIC           = 1879048241,
    DT_MIPS_PLTGOT                = 1879048242,
    DT_MIPS_RWPLT                 = 1879048244,
}


#[repr(C)]
#[derive(Debug, Copy)]
pub struct Elf_DynamicEntry_t {
    pub tag: DYNAMIC_TAGS,
    pub value: u64,
}


impl Clone for Elf_DynamicEntry_t {
    fn clone(&self) -> Self { *self }
}


#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SYMBOL_BINDINGS {
    STB_LOCAL      = 0,
    STB_GLOBAL     = 1,
    STB_WEAK       = 2,
    STB_GNU_UNIQUE = 10,
    STB_HIOS       = 12,
    STB_LOPROC     = 13,
    STB_HIPROC     = 15,
}


#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SYMBOL_TYPES {
    STT_NOTYPE    = 0,
    STT_OBJECT    = 1,
    STT_FUNC      = 2,
    STT_SECTION   = 3,
    STT_FILE      = 4,
    STT_COMMON    = 5,
    STT_TLS       = 6,
    STT_GNU_IFUNC = 10,
    STT_HIOS      = 12,
    STT_LOPROC    = 13,
    STT_HIPROC    = 15,
}


#[repr(C)]
#[derive(Debug, Copy)]
pub struct Elf_Symbol_t {
    pub name: *const c_char,
    pub type_: SYMBOL_TYPES,
    pub binding: SYMBOL_BINDINGS,
    pub information: u8,
    pub other: u8,
    pub shndx: u16,
    pub value: u64,
    pub size: u64,
}


impl Clone for Elf_Symbol_t {
    fn clone(&self) -> Elf_Symbol_t { *self }
}


#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SECTION_FLAGS {
    SHF_NONE             = 0,
    SHF_WRITE            = 1,
    SHF_ALLOC            = 2,
    SHF_EXECINSTR        = 4,
    SHF_MERGE            = 16,
    SHF_STRINGS          = 32,
    SHF_INFO_LINK        = 64,
    SHF_LINK_ORDER       = 128,
    SHF_OS_NONCONFORMING = 256,
    SHF_GROUP            = 512,
    SHF_TLS              = 1024,
    SHF_EXCLUDE          = 2147483648,
    XCORE_SHF_CP_SECTION = 2048,
    XCORE_SHF_DP_SECTION = 4096,
    SHF_MASKOS           = 267386880,
    SHF_MASKPROC         = 4026531840,
    SHF_X86_64_LARGE     = 268435456,
    SHF_MIPS_NODUPES     = 16777216,
    SHF_MIPS_NAMES       = 33554432,
    SHF_MIPS_LOCAL       = 67108864,
    SHF_MIPS_NOSTRIP     = 134217728,
    SHF_MIPS_MERGE       = 536870912,
    SHF_MIPS_ADDR        = 1073741824,
}


#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ELF_DATA { ELFDATANONE = 0, ELFDATA2LSB = 1, ELFDATA2MSB = 2, }


#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum OS_ABI {
    ELFOSABI_SYSTEMV      = 0,
    ELFOSABI_HPUX         = 1,
    ELFOSABI_NETBSD       = 2,
    ELFOSABI_GNU          = 3,
    ELFOSABI_HURD         = 4,
    ELFOSABI_SOLARIS      = 6,
    ELFOSABI_AIX          = 7,
    ELFOSABI_IRIX         = 8,
    ELFOSABI_FREEBSD      = 9,
    ELFOSABI_TRU64        = 10,
    ELFOSABI_MODESTO      = 11,
    ELFOSABI_OPENBSD      = 12,
    ELFOSABI_OPENVMS      = 13,
    ELFOSABI_NSK          = 14,
    ELFOSABI_AROS         = 15,
    ELFOSABI_FENIXOS      = 16,
    ELFOSABI_CLOUDABI     = 17,
    ELFOSABI_C6000_ELFABI = 64,
    ELFOSABI_C6000_LINUX  = 65,
    ELFOSABI_ARM          = 97,
    ELFOSABI_STANDALONE   = 255,
}


#[repr(C)]
#[derive(Debug, Copy)]
pub struct Elf_Binary_t {
    pub handler: *mut c_void,
    pub name: *const c_char,
    pub interpreter: *const c_char,
    pub type_: ELF_CLASS,
    pub header: Elf_Header_t,
    pub sections: *mut *mut Elf_Section_t,
    pub segments: *mut *mut Elf_Segment_t,
    pub dynamic_entries: *mut *mut Elf_DynamicEntry_t,
    pub dynamic_symbols: *mut *mut Elf_Symbol_t,
    pub static_symbols: *mut *mut Elf_Symbol_t,
}


impl Clone for Elf_Binary_t {
    fn clone(&self) -> Elf_Binary_t { *self }
}


#[link(name="LIEF")]
extern "C" {
    pub fn elf_parse(file: *const c_char) -> *mut Elf_Binary_t;
    pub fn elf_binary_destroy(binary: *mut Elf_Binary_t);
    pub fn elf_binary_save_header(binary: *mut Elf_Binary_t) -> c_int;

    pub fn SYMBOL_BINDINGS_to_string(e: SYMBOL_BINDINGS) -> *const c_char;
    pub fn E_TYPE_to_string(e: E_TYPE) -> *const c_char;
    pub fn VERSION_to_string(e: VERSION) -> *const c_char;
    pub fn ARCH_to_string(e: ARCH) -> *const c_char;
    pub fn SEGMENT_TYPES_to_string(e: SEGMENT_TYPES) -> *const c_char;
    pub fn DYNAMIC_TAGS_to_string(e: DYNAMIC_TAGS) -> *const c_char;
    pub fn SECTION_TYPES_to_string(e: SECTION_TYPES) -> *const c_char;
    pub fn SECTION_FLAGS_to_string(e: SECTION_FLAGS) -> *const c_char;
    pub fn SYMBOL_TYPES_to_string(e: SYMBOL_TYPES) -> *const c_char;
    pub fn ELF_CLASS_to_string(e: ELF_CLASS) -> *const c_char;
    pub fn ELF_DATA_to_string(e: ELF_DATA) -> *const c_char;
    pub fn OS_ABI_to_string(e: OS_ABI) -> *const c_char;
}

#[cfg(test)]
mod tests {
    // extern crate lief_sys;
    use super::*;

    #[allow(unused_imports)]
    use std::ffi::{CStr, CString};

    #[test]
    fn it_works() {
        let filename = CString::new("/bin/ls").unwrap().as_ptr();
        let _ = unsafe { elf_parse(filename) };
        // println!("hello");
    }
}
