/*
 * Mem Reduct Console (C++ Rewrite)
 *
 * This file is a rewritten, console-only derivative of Mem Reduct
 * originally developed by Henry++.
 *
 * Original project:
 *   https://github.com/henrypp/memreduct
 *
 * Changes from upstream:
 *   - Rewritten from C to C++
 *   - Consolidated into a single source file
 *   - Graphical user interface removed
 *   - Console-only execution with automatic default behavior
 *
 * License:
 *   GNU General Public License v3.0 (GPL-3.0)
 *
 * Original work by Henry++.
 * Modifications and rewrite by the maintainer of this repository.
 */

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <string>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// ==================== NT Type Definitions ====================
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0L)
#endif

#ifndef MAXSIZE_T
#define MAXSIZE_T SIZE_MAX
#endif

typedef enum _SYSTEM_INFORMATION_CLASS_EXT {
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    SystemRegistryReconciliationInformation = 84,
    SystemCombinePhysicalMemoryInformation = 130
} SYSTEM_INFORMATION_CLASS_EXT;

typedef enum _SYSTEM_MEMORY_LIST_COMMAND {
    MemoryEmptyWorkingSets = 2,
    MemoryPurgeLowPriorityStandbyList = 5
} SYSTEM_MEMORY_LIST_COMMAND;

typedef struct _SYSTEM_FILECACHE_INFORMATION {
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

typedef struct _MEMORY_COMBINE_INFORMATION_EX {
    HANDLE Handle;
    ULONG PagesCombined;
} MEMORY_COMBINE_INFORMATION_EX, *PMEMORY_COMBINE_INFORMATION_EX;

// Mount manager definitions
#define MOUNTMGR_DEVICE_NAME L"\\Device\\MountPointManager"
#define IOCTL_MOUNTMGR_QUERY_POINTS CTL_CODE(0x6D, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _MOUNTMGR_MOUNT_POINT {
    ULONG SymbolicLinkNameOffset;
    USHORT SymbolicLinkNameLength;
    USHORT Reserved1;
    ULONG UniqueIdOffset;
    USHORT UniqueIdLength;
    USHORT Reserved2;
    ULONG DeviceNameOffset;
    USHORT DeviceNameLength;
    USHORT Reserved3;
} MOUNTMGR_MOUNT_POINT, *PMOUNTMGR_MOUNT_POINT;

typedef struct _MOUNTMGR_MOUNT_POINTS {
    ULONG Size;
    ULONG NumberOfMountPoints;
    MOUNTMGR_MOUNT_POINT MountPoints[1];
} MOUNTMGR_MOUNT_POINTS, *PMOUNTMGR_MOUNT_POINTS;

#define MOUNTMGR_IS_VOLUME_NAME(name) \
    ((name)->Length >= 96 && \
     (name)->Buffer[0] == L'\\' && \
     (name)->Buffer[1] == L'?' && \
     (name)->Buffer[2] == L'?' && \
     (name)->Buffer[3] == L'\\' && \
     (name)->Buffer[4] == L'V' && \
     (name)->Buffer[5] == L'o' && \
     (name)->Buffer[6] == L'l' && \
     (name)->Buffer[7] == L'u' && \
     (name)->Buffer[8] == L'm' && \
     (name)->Buffer[9] == L'e' && \
     (name)->Buffer[10] == L'{')

// Memory cleaning masks (only those needed for default)
#define REDUCT_WORKING_SET              0x01
#define REDUCT_SYSTEM_FILE_CACHE        0x02
#define REDUCT_STANDBY_PRIORITY0_LIST   0x04
#define REDUCT_COMBINE_MEMORY_LISTS     0x20
#define REDUCT_REGISTRY_CACHE           0x40
#define REDUCT_MODIFIED_FILE_CACHE      0x80

#define REDUCT_MASK_DEFAULT (REDUCT_WORKING_SET | REDUCT_SYSTEM_FILE_CACHE | \
                             REDUCT_STANDBY_PRIORITY0_LIST | REDUCT_REGISTRY_CACHE | \
                             REDUCT_COMBINE_MEMORY_LISTS | REDUCT_MODIFIED_FILE_CACHE)

// Memory info structure
typedef struct _MEMORY_INFO {
    struct {
        ULONGLONG total_bytes;
        ULONGLONG free_bytes;
        ULONGLONG used_bytes;
        double percent_f;
        ULONG percent;
    } physical_memory;
    struct {
        ULONGLONG total_bytes;
        ULONGLONG free_bytes;
        ULONGLONG used_bytes;
        double percent_f;
        ULONG percent;
    } page_file;
    struct {
        ULONGLONG total_bytes;
        ULONGLONG free_bytes;
        ULONGLONG used_bytes;
        double percent_f;
        ULONG percent;
    } system_cache;
} MEMORY_INFO, *PMEMORY_INFO;

// ==================== NT Function Declarations ====================
extern "C" {
    NTSTATUS NTAPI NtSetSystemInformation(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength
    );
    
    NTSTATUS NTAPI NtCreateFile(
        PHANDLE FileHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        PLARGE_INTEGER AllocationSize,
        ULONG FileAttributes,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        PVOID EaBuffer,
        ULONG EaLength
    );
    
    NTSTATUS NTAPI NtDeviceIoControlFile(
        HANDLE FileHandle,
        HANDLE Event,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG IoControlCode,
        PVOID InputBuffer,
        ULONG InputBufferLength,
        PVOID OutputBuffer,
        ULONG OutputBufferLength
    );
    
    NTSTATUS NTAPI NtFlushBuffersFile(
        HANDLE FileHandle,
        PIO_STATUS_BLOCK IoStatusBlock
    );
    
    NTSTATUS NTAPI NtClose(HANDLE Handle);
    
    VOID NTAPI RtlInitUnicodeString(
        PUNICODE_STRING DestinationString,
        PCWSTR SourceString
    );
}

// ==================== Helper Functions ====================
bool IsElevated() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    
    TOKEN_ELEVATION elevation;
    DWORD size;
    bool result = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) 
                  && elevation.TokenIsElevated;
    
    CloseHandle(token);
    return result;
}

bool EnablePrivileges() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    
    const wchar_t* privilegeNames[] = {
        L"SeProfileSingleProcessPrivilege",
        L"SeIncreaseQuotaPrivilege"
    };
    
    bool success = true;
    for (const wchar_t* name : privilegeNames) {
        LUID luid;
        if (!LookupPrivilegeValueW(NULL, name, &luid)) {
            success = false;
            continue;
        }
        
        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        if (!AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL))
            success = false;
    }
    
    CloseHandle(token);
    return success;
}

void GetMemoryInfo(PMEMORY_INFO memInfo) {
    MEMORYSTATUSEX memStatus = { sizeof(memStatus) };
    GlobalMemoryStatusEx(&memStatus);
    
    memInfo->physical_memory.total_bytes = memStatus.ullTotalPhys;
    memInfo->physical_memory.free_bytes = memStatus.ullAvailPhys;
    memInfo->physical_memory.used_bytes = memStatus.ullTotalPhys - memStatus.ullAvailPhys;
    memInfo->physical_memory.percent_f = static_cast<double>(memStatus.dwMemoryLoad);
    memInfo->physical_memory.percent = memStatus.dwMemoryLoad;
    
    memInfo->page_file.total_bytes = memStatus.ullTotalPageFile;
    memInfo->page_file.free_bytes = memStatus.ullAvailPageFile;
    memInfo->page_file.used_bytes = memStatus.ullTotalPageFile - memStatus.ullAvailPageFile;
    memInfo->page_file.percent_f = memStatus.ullTotalPageFile ? 
        (100.0 * memInfo->page_file.used_bytes / memStatus.ullTotalPageFile) : 0.0;
    memInfo->page_file.percent = static_cast<ULONG>(memInfo->page_file.percent_f);
    
    PERFORMANCE_INFORMATION perfInfo = { sizeof(perfInfo) };
    if (GetPerformanceInfo(&perfInfo, sizeof(perfInfo))) {
        memInfo->system_cache.total_bytes = perfInfo.SystemCache * perfInfo.PageSize;
        memInfo->system_cache.used_bytes = perfInfo.KernelTotal * perfInfo.PageSize;
        memInfo->system_cache.free_bytes = memInfo->system_cache.total_bytes - 
                                           memInfo->system_cache.used_bytes;
        memInfo->system_cache.percent_f = memInfo->system_cache.total_bytes ?
            (100.0 * memInfo->system_cache.used_bytes / memInfo->system_cache.total_bytes) : 0.0;
        memInfo->system_cache.percent = static_cast<ULONG>(memInfo->system_cache.percent_f);
    }
}

std::string FormatBytesize64(ULONGLONG bytes) {
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }
    
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%.2f %s", size, units[unit]);
    return std::string(buffer);
}

bool IsWindowsVersionOrGreater(DWORD major, DWORD minor) {
    OSVERSIONINFOEXW osvi = { sizeof(osvi), 0 };
    osvi.dwMajorVersion = major;
    osvi.dwMinorVersion = minor;
    
    DWORDLONG condMask = 0;
    condMask = VerSetConditionMask(condMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    condMask = VerSetConditionMask(condMask, VER_MINORVERSION, VER_GREATER_EQUAL);
    
    return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION, condMask) != FALSE;
}

// ==================== Volume Cache Flushing ====================
NTSTATUS FlushVolumeCacheAccurate() {
    UNICODE_STRING deviceName;
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    IO_STATUS_BLOCK iosb;
    HANDLE hDevice = NULL;
    NTSTATUS status;
    
    RtlInitUnicodeString(&deviceName, MOUNTMGR_DEVICE_NAME);
    oa.Length = sizeof(oa);
    oa.ObjectName = &deviceName;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    
    status = NtCreateFile(
        &hDevice,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    
    if (!NT_SUCCESS(status)) {
        printf("FAILED (0x%08X)\n", status);
        return status;
    }
    
    MOUNTMGR_MOUNT_POINT input = {0};
    BYTE buffer[16384];
    PMOUNTMGR_MOUNT_POINTS mountPoints = (PMOUNTMGR_MOUNT_POINTS)buffer;
    
    status = NtDeviceIoControlFile(
        hDevice,
        NULL,
        NULL,
        NULL,
        &iosb,
        IOCTL_MOUNTMGR_QUERY_POINTS,
        &input,
        sizeof(input),
        mountPoints,
        sizeof(buffer)
    );
    
    if (!NT_SUCCESS(status)) {
        printf("FAILED (0x%08X)\n", status);
        NtClose(hDevice);
        return status;
    }
    
    ULONG flushedCount = 0;
    for (ULONG i = 0; i < mountPoints->NumberOfMountPoints; i++) {
        PMOUNTMGR_MOUNT_POINT mp = &mountPoints->MountPoints[i];
        
        UNICODE_STRING volumeName;
        volumeName.Length = mp->SymbolicLinkNameLength;
        volumeName.MaximumLength = mp->SymbolicLinkNameLength + sizeof(WCHAR);
        volumeName.Buffer = (PWSTR)((PBYTE)mountPoints + mp->SymbolicLinkNameOffset);
        
        if (MOUNTMGR_IS_VOLUME_NAME(&volumeName)) {
            OBJECT_ATTRIBUTES volOa = { sizeof(volOa) };
            volOa.Length = sizeof(volOa);
            volOa.ObjectName = &volumeName;
            volOa.Attributes = OBJ_CASE_INSENSITIVE;
            
            HANDLE hVolume;
            IO_STATUS_BLOCK volIosb;
            
            status = NtCreateFile(
                &hVolume,
                FILE_WRITE_DATA | SYNCHRONIZE,
                &volOa,
                &volIosb,
                NULL,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                NULL,
                0
            );
            
            if (NT_SUCCESS(status)) {
                status = NtFlushBuffersFile(hVolume, &volIosb);
                if (NT_SUCCESS(status)) {
                    flushedCount++;
                }
                NtClose(hVolume);
            }
        }
    }
    
    NtClose(hDevice);
    printf("OK (flushed %lu volumes)\n", flushedCount);
    return STATUS_SUCCESS;
}

// ==================== Core Cleaning Logic (Simplified) ====================
void CleanMemory() {
    printf("Starting memory cleanup with default mask: 0x%02X\n", REDUCT_MASK_DEFAULT);
    
    printf("\nEnabled operations:\n");
    printf("  [X] Working set\n");
    printf("  [X] System file cache\n");
    printf("  [X] Modified file cache\n");
    printf("  [X] Standby priority-0 list\n");
    printf("  [X] Registry cache (Win8.1+)\n");
    printf("  [X] Combine memory lists (Win10+)\n");
    printf("\n");
    
    if (!EnablePrivileges()) {
        printf("Warning: Failed to enable some privileges\n");
    }
    
    MEMORY_INFO memInfoBefore, memInfoAfter;
    GetMemoryInfo(&memInfoBefore);
    ULONGLONG reductBefore = memInfoBefore.physical_memory.used_bytes;
    
    printf("Memory before: %s used\n\n", FormatBytesize64(reductBefore).c_str());
    printf("Executing cleanup operations:\n");
    
    NTSTATUS status;
    
    // 1. Working set
    printf("  -> Emptying working sets... ");
    SYSTEM_MEMORY_LIST_COMMAND command = MemoryEmptyWorkingSets;
    status = NtSetSystemInformation(SystemMemoryListInformation, &command, sizeof(command));
    printf(!NT_SUCCESS(status) ? "FAILED (0x%08X)\n" : "OK\n", status);
    
    // 2. System file cache
    printf("  -> Clearing system file cache... ");
    SYSTEM_FILECACHE_INFORMATION sfci = {0};
    sfci.MinimumWorkingSet = MAXSIZE_T;
    sfci.MaximumWorkingSet = MAXSIZE_T;
    status = NtSetSystemInformation(SystemFileCacheInformationEx, &sfci, sizeof(sfci));
    printf(!NT_SUCCESS(status) ? "FAILED (0x%08X)\n" : "OK\n", status);
    
    // 3. Flush volume cache
    printf("  -> Flushing volume cache... ");
    FlushVolumeCacheAccurate();
    
    // 4. Standby priority-0 list
    printf("  -> Purging low priority standby list... ");
    command = MemoryPurgeLowPriorityStandbyList;
    status = NtSetSystemInformation(SystemMemoryListInformation, &command, sizeof(command));
    printf(!NT_SUCCESS(status) ? "FAILED (0x%08X)\n" : "OK\n", status);
    
    // 5. Flush registry cache
    if (IsWindowsVersionOrGreater(6, 3)) {
        printf("  -> Flushing registry cache... ");
        status = NtSetSystemInformation(SystemRegistryReconciliationInformation, NULL, 0);
        printf(!NT_SUCCESS(status) ? "FAILED (0x%08X)\n" : "OK\n", status);
    } else {
        printf("  -> Skipping registry cache (requires Windows 8.1+)\n");
    }
    
    // 6. Combine memory lists
    if (IsWindowsVersionOrGreater(10, 0)) {
        printf("  -> Combining memory lists... ");
        MEMORY_COMBINE_INFORMATION_EX combineInfo = {0};
        status = NtSetSystemInformation(SystemCombinePhysicalMemoryInformation, 
                                       &combineInfo, sizeof(combineInfo));
        printf(!NT_SUCCESS(status) ? "FAILED (0x%08X)\n" : "OK\n", status);
    } else {
        printf("  -> Skipping memory combine (requires Windows 10+)\n");
    }
    
    GetMemoryInfo(&memInfoAfter);
    ULONGLONG reductAfter = memInfoAfter.physical_memory.used_bytes;
    ULONGLONG freed = (reductAfter < reductBefore) ? (reductBefore - reductAfter) : 0;
    
    printf("\n========================================\n");
    printf("Cleanup completed!\n");
    printf("Memory freed: %s\n", FormatBytesize64(freed).c_str());
    printf("Current usage: %s / %s (%.1f%%)\n",
        FormatBytesize64(reductAfter).c_str(),
        FormatBytesize64(memInfoAfter.physical_memory.total_bytes).c_str(),
        memInfoAfter.physical_memory.percent_f);
    printf("========================================\n");
}

// ==================== Main Entry Point ====================
int main() {
    printf("===============================================\n");
    printf("Memory Cleaner Console - Default Mode Only\n");
    printf("Port from Mem Reduct v3.5.2 by Henry++\n");
    printf("===============================================\n\n");
    
    if (!IsElevated()) {
        printf("ERROR: Administrator privileges required!\n");
        printf("Please right-click and select 'Run as administrator'\n\n");
        printf("Press Enter to exit...");
        getchar();
        return 1;
    }
    
    CleanMemory();
    
    printf("\nPress Enter to exit...");
    getchar();
    return 0;
}