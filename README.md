# MachO

A relatively simple library for parsing and manipulating MachO files and their CMS blobs. Written for exploitation of [CVE-2023-41991](https://support.apple.com/en-gb/HT213926), a vulnerability in the CoreTrust kernel extension.

The library works primarily on iOS binaries, and should work on macOS binaries too, but this is not guaranteed. It's written entirely in C, so it's both fast and portable to iOS (for TrollStore or similar apps) as well as most other devices - however, due to the fact that it is in C, a malformed MachO could cause a memory fault, so I cannot guarantee that this parser will work correctly for such binaries.

Thin MachO binaries that are built for ARMv7, or FAT binaries with ARMv7 slices, are currently unsupported for parsing. More handling of such files is planned, but full ARMv7 support is not planned at the moment.

## Usage

To use the library, you can either compile with `make all`, to have an executable that demonstrates the abilities of this library, or you can simply drop the header files and their relevant `.c` files into your project folder and just include the ones you need.

Use `getPreferredSliceIndex(MachO *macho)` to get the index of the preferred architecture slice in a FAT MachO. This is the slice that will be executed by the host device if you were to run the binary. If you're using a thin MachO, this function will just return index 0, or -1 if the architechture does not match.

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

## Additional credits

Thank you to the checkra1n team for libDER, taken from [PongoOS](https://github.com/checkra1n/PongoOS/tree/iOS15) and licensed under the [MIT license](https://github.com/checkra1n/PongoOS/tree/iOS15/LICENSE.md). Related files are in [lib/include/libDER](lib/include/libDER).