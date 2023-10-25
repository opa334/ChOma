* Add ability to insert SignerInfo and CertificateSet elements into SignedData
* Support DER encoding of ContentInfo
* Add support for parsing requirement blob
* Add support for manipulating the CodeDirectory blob
* Add support for arbitrarily inserting a blob into a MachO file
* Somewhat handle ARMv7 slices (no need to parse them, but don't crash or reject them)
* Create the MachOBuilder structure to help rebuild MachO files