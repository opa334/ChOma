* Add ability to insert SignerInfo and CertificateSet elements into SignedData
* Support DER encoding of ContentInfo
* Add support for parsing requirement blob
* Add support for manipulating the CodeDirectory blob
* Add support for arbitrarily inserting a blob into a MachO file
* Create the MachOBuilder structure to help rebuild MachO files
* Change all `macho_` functions to use a `MachOSlice` structure instead of a `MachO` structure
* Support extracting the DER signature blob from the MachO and parsing it