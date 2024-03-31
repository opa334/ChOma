# ChOma

ChOma is a simple library for parsing and manipulating MachO files and their CMS blobs. Written for exploitation of [CVE-2023-41991](https://support.apple.com/en-gb/HT213926), a vulnerability in the CoreTrust kernel extension, and for use in [TrollStore](https://github.com/opa334/TrollStore) and [XPF](https://github.com/opa334/XPF) (which is used by [Dopamine](https://github.com/opa334/Dopamine) as its kernel patchfinder)

## Compilation

### Building for macOS
`make`

### Building for iOS
`make TARGET=ios`

### Additional Options
`DEBUG=1`: Build with address sanitizer

`DISABLE_SIGNING=1`: Disable all features that depend on OpenSSL

`DISABLE_TESTS=1`: Don't build tests

`INSTALL_PATH=/some/path`: Path where ChOma gets installed to when using `make install`

## Usage

To use the library, you can compile with `make all`. This will produce the `choma_cli` executable that demonstrates the abilities of this library, and then `libchoma.a` and `libchoma.dylib` which can be linked to your own project.

In `output/tests`, you will find `choma_cli` and `ct_bypass`. `choma_cli` is a simple CLI tool that demonstrates the abilities of this library, and `ct_bypass` is a proof-of-concept exploit for CVE-2023-41991 that uses this library. `ct_bypass` only works on iOS binaries, as trying to use macOS binaries will result in the bypass being unsuccessful as we use an iOS identity to insert into the code signature.

## CoreTrust bypass

ChOma was written primarily for the purpose of exploiting CVE-2023-41991, which allows a binary to bypass CoreTrust during code-signing and appear as an App Store-signed binary. As a result, binaries can be permanently signed on device and have arbitrary entitlements, apart from a few restricted ones that are only allowed to be used by trustcached binaries.

The vulnerability is caused by CoreTrust incorrectly handling multiple SignerInfo structures in a CMS blob. By having one SignerInfo that contains a valid signature (but from an identity that is not trusted by CoreTrust), and another SignerInfo that contains an invalid signature (but from an App Store identity), we can trick CoreTrust into thinking that the binary is signed by the App Store identity, and therefore allow it to be executed.

The exploit is implemented in `ct_bypass`, and works by:
1. Taking a pseudo-signed binary (a binary that has been signed by `ldid`).
2. Updating the load commands by calculating the new sizes of the __LINKEDIT segment and the code signature.
3. Updating the page hashes in the SHA256 CodeDirectory to match the new load command data.
4. Replacing the SHA1 CodeDirectory with one from a valid App Store-signed binary.
5. Inserting a template signature blob into the code signature, containing two SignerInfo structures.
6. Updating the necessary fields in the signature blob to match the CD hashes.
7. Signing the signature blob for the custom identity (the App Store identity will already have an intact signature).
8. Inserting the new code signature into the binary.

## Terminology

Inside ChOma, there are a few terms that are used to describe various parts of the MachO file. These are:
- **FAT** - represents a FAT MachO file (a MachO file that contains multiple slices, which are each a MachO file for a different architecture).
- **MachO** - represents either a single-architecture MachO file, or a slice of a FAT MachO file.

## Underlying mechanisms
ChOma uses the `MemoryBuffer` structure to provide a unified way to read, write, shrink and expand data buffers, that works across both files and memory. Each `MemoryBuffer` has a `context` field that determines whether the functions interpret it as a `BufferedStream` object (for regular memory buffers) or as a `FileStream` object (for files).

Each `MemoryBuffer` object contains function pointers for reading, writing, retrieving the size, expanding, shrinking and then soft or hard cloning. You can inspect these inside [`src/MemoryBuffer.h`](src/MemoryStream.h), and can see how they are used by looking at how we manipulate MachO files across the library.
