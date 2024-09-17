# ChOma

ChOma is a simple library for parsing and manipulating MachO files and their CMS blobs. Written for exploitation of [CVE-2023-41991](https://support.apple.com/en-gb/HT213926), a vulnerability in the CoreTrust kernel extension, and for use in [TrollStore](https://github.com/opa334/TrollStore) and [XPF](https://github.com/opa334/XPF) (which is used by [Dopamine](https://github.com/opa334/Dopamine) as the kernel patchfinder)

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

To use the library, you can compile with `make all`. This will produce `libchoma.a` and `libchoma.dylib`, which can be linked to your own project, as well as multiple test binaries:
* `choma_cli` - a binary to demonstrate the features of ChOma
* `ct_bypass` - a binary that use CVE-2023-41991 to apply a CoreTrust bypass to an iOS binary
* `dyld_patch` - a binary that will patch an iOS 15+ dyld binary to ignore AMFI flags (used by Dopamine)
* `fat_create` - a binary that will create a fat MachO out of a selection of MachOs, ignoring all CPU types and subtypes
* `kpf` - a binary that was used to begin writing a kernel patchfinder used in Dopamine 2.0, superseded by [XPF](https://github.com/opa334/XPF)

## CoreTrust bypass

ChOma was written primarily for the purpose of exploiting CVE-2023-41991, which allows a binary to bypass CoreTrust during code-signing and appear as an App Store-signed binary. As a result, binaries can be permanently signed on device and have arbitrary entitlements, apart from a few restricted ones that are only allowed to be used by trustcached binaries.

The vulnerability is caused by CoreTrust incorrectly handling multiple signers in a CMS signature blob. The signature blob will have two signers: the App Store certificate chain (which has a valid signature for a different code signature) and a custom certificate chain (which has a valid signature for our code signature). Due to it incorrectly validating both signers, CoreTrust will return the CD hashes from our signer but set the policy flags using the App Store signer.

The exploit is implemented in `ct_bypass`, and works by:
1. Updating the load commands by calculating the new sizes of the __LINKEDIT segment and the code signature.
2. Updating the page hashes in the SHA256 CodeDirectory to match the new load command data.
3. Replacing the SHA1 CodeDirectory with one from a valid App Store binary.
4. Creating a new signature blob that has two signers, the App Store and our custom certificate chain.
5. Updating the necessary fields in the signature blob to match the CD hashes.
6. Signing the signature blob for the custom identity (the App Store identity will already have an intact signature).
7. Inserting the new code signature into the binary.

## Terminology

Inside ChOma, there are a few terms that are used to describe various parts of the MachO file. These are:
- **Fat** - represents a Fat MachO file (a MachO file that contains multiple slices, which are each a MachO file for a different architecture).
- **MachO** - represents either a single-architecture MachO file, or a slice of a Fat MachO file.

## Underlying mechanisms
ChOma uses the `MemoryBuffer` structure to provide a unified way to read, write, shrink and expand data buffers, that works across both files and memory. Each `MemoryBuffer` has a `context` field that determines whether the functions interpret it as a `BufferedStream` object (for regular memory buffers) or as a `FileStream` object (for files).

Each `MemoryBuffer` object contains function pointers for reading, writing, retrieving the size, expanding, shrinking and then soft or hard cloning. You can inspect these inside [`src/MemoryBuffer.h`](src/MemoryStream.h), and can see how they are used by looking at how we manipulate MachO files across the library.
