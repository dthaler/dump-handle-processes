#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#include <winternl.h>
#pragma comment(lib, "ntdll.lib")
#include <ntstatus.h>

#pragma comment(lib, "psapi.lib")
#define PSAPI_VERSION 1
#include <psapi.h>
#include <processsnapshot.h>

#define SystemHandleInformation ((SYSTEM_INFORMATION_CLASS)16)

typedef struct
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    void* Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE;

typedef struct
{
    ULONG Count;
    SYSTEM_HANDLE Handles[0];
} SYSTEM_HANDLE_INFORMATION;

typedef enum
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE;

typedef struct
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
    char more[16];
} OBJECT_TYPE_INFORMATION;

void PrintProcessHandles(HANDLE process_handle)
{
    DWORD handle_count;
    if (!GetProcessHandleCount(process_handle, &handle_count)) {
        return;
    }

    size_t shsize = sizeof(SYSTEM_HANDLE);
    ULONG bytes_needed = 0;
    ULONG handle_information_size = 32;
    SYSTEM_HANDLE_INFORMATION* handle_information = (SYSTEM_HANDLE_INFORMATION*)malloc(handle_information_size);
    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, handle_information, handle_information_size, &bytes_needed);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        free(handle_information);
        handle_information_size = bytes_needed;
        handle_information = (SYSTEM_HANDLE_INFORMATION*)malloc(handle_information_size);
        status = NtQuerySystemInformation(SystemHandleInformation, handle_information, handle_information_size, &bytes_needed);
        if (NT_ERROR(status)) {
            for (ULONG i = 0; i < handle_information->Count; i++) {
                printf("PID %d: handle %x\n", handle_information->Handles[i].ProcessId, handle_information->Handles[i].Handle);
                printf("  type: %d\n", handle_information->Handles[i].ObjectTypeNumber);

                /* Query the object type. */
                OBJECT_TYPE_INFORMATION object_type_info;
                status = NtQueryObject((HANDLE)handle_information->Handles[i].Handle, ObjectTypeInformation, &object_type_info, sizeof(object_type_info), &bytes_needed);
                if (NT_ERROR(status)) {
                    printf("  Name: <unknown>\n");
                } else {
                    printf("  Name: %ls\n", object_type_info.Name.Buffer);
                }

                /* Query eBPF for its type info. */
                // We could use the QUERY_PROGRAM_INFO ioctl to get this. Or we could move this logic into kernel mode
                // and avoid all the user-kernel transitions, which seems better.
            }
            return;
        }
        free(handle_information);
    }

#if 0
    PROCESS_HANDLE_INFORMATION handle_information;
    NTSTATUS status = NtQueryInformationProcess(process_handle, ProcessHandleCount,
#endif

    HPSS snapshot_handle = nullptr;
    // The following work but don't get handle information:
    //  PSS_CAPTURE_HANDLE_BASIC_INFORMATION
    //  PSS_CAPTURE_HANDLE_NAME_INFORMATION
    //  PSS_CAPTURE_THREADS
    PSS_CAPTURE_FLAGS capture_flags = PSS_CAPTURE_THREADS;
    DWORD result = PssCaptureSnapshot(process_handle, capture_flags, 0, &snapshot_handle);
    if (result != ERROR_SUCCESS) {
        printf("Error %d\n", result);
        return;
    }
    PSS_PROCESS_INFORMATION process_information;
    result = PssQuerySnapshot(snapshot_handle, PSS_QUERY_PROCESS_INFORMATION, &process_information, sizeof(process_information));
    PSS_HANDLE_INFORMATION pss_handle_information;
    result = PssQuerySnapshot(snapshot_handle, PSS_QUERY_HANDLE_INFORMATION, &pss_handle_information, sizeof(pss_handle_information));

    HPSSWALK walk_marker_handle;
    result = PssWalkMarkerCreate(nullptr, &walk_marker_handle);
    if (result == ERROR_SUCCESS) {
        PSS_HANDLE_ENTRY handle_entry;
        for (;;) {
            result = PssWalkSnapshot(snapshot_handle, PSS_WALK_HANDLES, walk_marker_handle, &handle_entry, sizeof(handle_entry));
            if (result != ERROR_SUCCESS) {
                break;
            }
            printf("  Handle: %p\n", handle_entry.Handle);
        }

        PssWalkMarkerFree(walk_marker_handle);
    }
    PssFreeSnapshot(process_handle, snapshot_handle);
}

void PrintProcessNameAndID(DWORD process_id)
{
    TCHAR process_name[MAX_PATH] = TEXT("<unknown>");

    HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, process_id);

    if (process_handle == nullptr) {
        return;
    }

    (void)GetModuleBaseName(process_handle, nullptr, process_name, sizeof(process_name) / sizeof(*process_name));
    _tprintf(TEXT("%s  (PID: %u)\n"), process_name, process_id);

    PrintProcessHandles(process_handle);

    CloseHandle(process_handle);
}

int main(void)
{
    DWORD max_processes = 512;
    DWORD bytes_used;
    DWORD* processes = nullptr;
    DWORD process_count;

    // Get the list of process identifiers.
    do {
        max_processes *= 2;
        delete[] processes;
        processes = new DWORD[max_processes];
        if (!EnumProcesses(processes, max_processes * sizeof(DWORD), &bytes_used)) {
            return 1;
        }

        // Calculate how many process identifiers were returned.
        process_count = bytes_used / sizeof(DWORD);
    } while (process_count == max_processes);

    // Print the name and process identifier for each process.
    for (DWORD i = 0; i < process_count; i++) {
        if (processes[i] != 0) {
            PrintProcessNameAndID(processes[i]);
        }
    }

    delete[] processes;
    return 0;
}
