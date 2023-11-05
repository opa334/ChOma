#include "Host.h"

int host_get_cpu_information(cpu_type_t *cputype, cpu_subtype_t *cpusubtype) {
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

int macho_container_get_preferred_macho_index(MachOContainer *machOContainer) {
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    if (host_get_cpu_information(&cputype, &cpusubtype) != 0) { return -1; }
    for (int i = 0; i < machOContainer->machoCount; i++) {
        if (machOContainer->machos[i].archDescriptor.cputype == cputype
        && machOContainer->machos[i].archDescriptor.cpusubtype == cpusubtype
        && machOContainer->machos[i].isSupported) {
            return i;
        }
    }
    printf("Error: failed to find a valid, preferred macho.\n");
    return -1;
}