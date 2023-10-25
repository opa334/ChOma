#include "Host.h"

int getInformation(cpu_type_t *cputype, cpu_subtype_t *cpusubtype) {
    size_t len;
    
    // Query for cputype
    len = sizeof(cputype);
    if (sysctlbyname("hw.cputype", cputype, &len, NULL, 0) == -1) { printf("ERROR: no cputype.\n"); return -1; }
    
    // Query for cpusubtype
    len = sizeof(cpusubtype);
    if (sysctlbyname("hw.cpusubtype", cpusubtype, &len, NULL, 0) == -1) { printf("ERROR: no cpusubtype.\n"); return -1; }
    
    printf("cputype: 0x%x, cpusubtype: %d.\n", *cputype, *cpusubtype);
    return 0;
}

int getPreferredSliceIndex(MachO *macho) {
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    if (getInformation(&cputype, &cpusubtype) != 0) { return -1; }
    for (int i = 0; i < macho->_sliceCount; i++) {
        if (macho->_slices[i]._archDescriptor.cputype == cputype
        && macho->_slices[i]._archDescriptor.cpusubtype == cpusubtype
        && macho->_slices[i]._isValid) {
            return i;
        }
    }
    printf("Error: failed to find a valid, preferred slice.\n");
    return -1;
}