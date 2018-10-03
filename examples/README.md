**Examples**

- pereader: a simple clone of [pereader](https://github.com/lief-project/LIEF/blob/master/examples/c/pe_reader.c)

```
cd pereader
cargo build
cargo run -- C:\Windows\System32\notepad.exe

File:                            notepad.exe
                                 
DOS header                       =================
Used bytes in the last page:     0x90
File size in pages:              0x3
Number of relocations:           0x0
Header size in paragraphs:       0x4
Minimum extra paragraphs:        0x0
Maximum extra paragraphs:        0xffff
Initial relative stack segment:  0x0
Initial stack pointer:           0xb8
Checksum:                        0x0
Initial relative code segment:   0x0
Checksum:                        0x0
Address of relocation table:     0x40
Overlay number:                  0x0
OEM id:                          0x0
OEM info:                        0x0
Address of PE header:            0xe8
                                 
PE header                        =================
Machine:                         AMD64
Number of sections:              6
Timestamp:                       2040-03-17 08:27:10
Pointer to symbol table:         0x0
Number of symbols:               0
Sizeof optional header:          0xf0
Characteristics:                 0x22
                                 
Optional header                  =================
Magic:                           PE32_PLUS
Major linker version:            0xe
Minor linker version:            0xc
Size ofcode:                     0x18e00
Size of initialized data:        0x25000
Size of uninitialized data:      0x0
Address of entrypoint:           0x19180
Base of code:                    0x1000
Base of data:                    0x0
Image base:                      0x140000000
Section alignment:               0x1000
File alignment:                  0x200
Major operating system version:  0xa
Minor operating system version:  0x0
Major image version:             0xa
Minor image version:             0x0
Major subsystem version:         0xa
Minor subsystem version:         0x0
Win32 version value:             0x0
Size of image:                   0x41000
Size of headers:                 0x400
Checksum:                        0x41603
Subsystem:                       WINDOWS_GUI
DLL characteristics:             0xc160
Size of stack reserve:           0x80000
Size of stack commit:            0x11000
Size of heap reserve:            0x100000
Size of heap commit:             0x1000
Loader flags:                    0x0
Number of rva and size:          0x10
```

- wcs: a clone of [winchecksec](https://github.com/trailofbits/winchecksec)

```
cd wcs
cargo build
cargo run -- C:\Windows\System32\notepad.exe

Dynamic base:                         true
ASLR:                                 false
High entropy ASLR:                    false
Force integrity:                      false
Isolation:                            true
NX protection:                        true
Structured exception handling (SEH):  true
Control flow guard:                   true
Return flow guard:                    false
Safe SEH:                             true
Buffer security check:                true
.NET:                                 false
```