# MachO

A relatively simple library for parsing and manipulating MachO files and their CMS blobs. Written for exploitation of [CVE-2023-41991](https://support.apple.com/en-gb/HT213926), a vulnerability in the CoreTrust kernel extension.

The library works primarily on iOS binaries, I have seen issues (segmentation faults) when trying to parse macOS binaries, so your mileage may vary with such executables. It's written entirely in C, so it's both fast and portable to iOS (for TrollStore or similar apps) as well as most other devices - however, due to the fact that it is in C, a malformed MachO could likely cause a memory fault quite easily, so I cannot guarantee that this parser will work correctly.

This library relies on zero external libraries or dependences, so you can simply build `main.c` with `gcc *.c -o parser`.

## Usage

To use the library, you can either compile with `main.c` as shown above, to have an executable that demonstrates the abilities of this library, or you can simply drop the header files and their relevant `.c` files into your project folder and just include the ones you need.

## Relevant MachO File Structures

Inside each single-architecture MachO (or alternatively each slice of a MachO), the first structure is either `mach_header` or `mach_header_64`, which contains information about the executable:
```c
/*
 * The mach header appears at the very beginning of the object file; it
 * is the same for both 32-bit and 64-bit architectures.
 */
struct mach_header {
	uint32_t	magic;		/* mach magic number identifier */
	cpu_type_t	cputype;	/* cpu specifier */
	cpu_subtype_t	cpusubtype;	/* machine specifier */
	uint32_t	filetype;	/* type of file */
	uint32_t	ncmds;		/* number of load commands */
	uint32_t	sizeofcmds;	/* the size of all the load commands */
	uint32_t	flags;		/* flags */
};

/*
 * The 64-bit mach header appears at the very beginning of object files for
 * 64-bit architectures.
 */
struct mach_header_64 {
	uint32_t	magic;		/* mach magic number identifier */
	cpu_type_t	cputype;	/* cpu specifier */
	cpu_subtype_t	cpusubtype;	/* machine specifier */
	uint32_t	filetype;	/* type of file */
	uint32_t	ncmds;		/* number of load commands */
	uint32_t	sizeofcmds;	/* the size of all the load commands */
	uint32_t	flags;		/* flags */
	uint32_t	reserved;	/* reserved */
};
```
Note: if you have a FAT MachO (multiple architectures inside one file), the first structure is a `fat_header`, which contains information about the architectures inside the file:
```c
struct fat_header {
	unsigned long	magic;		/* FAT_MAGIC */
	unsigned long	nfat_arch;	/* number of structs that follow */
};
```
Each 'slice' will have it's `fat_arch` structure to provide relevant information about the architecture:
```c
struct fat_arch {
	cpu_type_t	cputype;	/* cpu specifier (int) */
	cpu_subtype_t	cpusubtype;	/* machine specifier (int) */
	unsigned long	offset;		/* file offset to this object file */
	unsigned long	size;		/* size of this object file */
	unsigned long	align;		/* alignment as a power of 2 */
};
```

After the `mach_header` or `mach_header_64` structure, there are a number of `load_command` structures, which contain information about the various segments and sections inside the MachO:
```c
struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
    /* More command-specific fields follow */
};
```
To see some examples of load commands, try parsing an iOS MachO with this library and printing the `cmd` field of each load command, using `loadCommandToName(int loadCommand)` to see which command it is.

Following the load commands, there are 'segments' of code that are loaded into memory. Each segment has a number of sections, which contain the actual code and data. The contents of sections and segments is not too relevant to the CoreTrust bug, so I didn't spend much time researching them. However, more information can be found online with a quick search.