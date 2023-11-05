#ifndef HOST_H
#define HOST_H

#include <stdio.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/machine.h>

#include "MachOContainer.h"

// Retrieve the index of the slice preferred by the host
int macho_get_preferred_slice_index(MachOContainer *macho);

#endif // HOST_H