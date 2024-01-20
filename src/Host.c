#include "Host.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/machine.h>

int host_get_cpu_information(cpu_type_t *cputype, cpu_subtype_t *cpusubtype)
{
    size_t len;
    
    // Query for cputype
    len = sizeof(cputype);
    if (sysctlbyname("hw.cputype", cputype, &len, NULL, 0) == -1) { printf("ERROR: no cputype.\n"); return -1; }
    
    // Query for cpusubtype
    len = sizeof(cpusubtype);
    if (sysctlbyname("hw.cpusubtype", cpusubtype, &len, NULL, 0) == -1) { printf("ERROR: no cpusubtype.\n"); return -1; }
    
    return 0;
}

MachO *fat_find_preferred_slice(FAT *fat)
{
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    if (host_get_cpu_information(&cputype, &cpusubtype) != 0) { return NULL; }
    
    MachO *preferredMacho = NULL;

    // If you intend on supporting non darwin, implement platform specific logic here using #ifdef's
    if (cputype == CPU_TYPE_ARM64) {
        if (cpusubtype == CPU_SUBTYPE_ARM64E) {
            // If this is an arm64e device, first try to find a new ABI arm64e slice
            // TODO: Gate this behind iOS 14+?
            preferredMacho = fat_find_slice(fat, cputype, (CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2));
            if (!preferredMacho) {
                // If that's not found, try to find an old ABI arm64e slice
                preferredMacho = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64E);
            }
        }

        if (!preferredMacho) {
            // If not arm64e device or no arm64e slice found, try to find regular arm64 slice

            // On iOS 15+, the Kernel prefers an arm64v8 slice to an arm64 slice, so check that first
            // TODO: Gate this behind iOS 15+?
            preferredMacho = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_V8);
            if (!preferredMacho) {
                // If that's not found, finally check for a regular arm64 slice
                preferredMacho = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_ALL);
            }
        }
    }

    if (!preferredMacho) {
        printf("Error: failed to find a preferred MachO slice that matches the host architecture.\n");
    }
    return preferredMacho;
}