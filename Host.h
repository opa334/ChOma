#ifndef HOST_H
#define HOST_H

#include "MachOContainer.h"

// Retrieve the preferred MachO slice from a MachO container
MachO *macho_container_find_preferred_macho_slice(MachOContainer *machoContainer);

#endif // HOST_H