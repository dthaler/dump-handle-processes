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
    SYSTEM_HANDLE Handles[1];
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

void PrintHandleInfo(HANDLE process_handle, HANDLE other_handle)
{
    char buffer[1024];
    ULONG buffer_size = sizeof(buffer);
    ULONG bytes_needed;
    NTSTATUS status;

    printf(" Handle: %p\n", other_handle);

    HANDLE target_handle;
    if (!DuplicateHandle(
        process_handle,
        other_handle,
        GetCurrentProcess(),
        &target_handle,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS)) {
        printf("DuplicateHandle failed with error %d\n", GetLastError());
        return;
    }

#if 0
    // Query the object basic info.
    PUBLIC_OBJECT_BASIC_INFORMATION* object_basic_info = (PUBLIC_OBJECT_BASIC_INFORMATION*)buffer;
    bytes_needed = 0;
    status = NtQueryObject(target_handle, ObjectBasicInformation, object_basic_info, buffer_size, &bytes_needed);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        printf("  Length needed to get HandleCount: %d\n", bytes_needed);
    }
    if (NT_ERROR(status)) {
        printf("  HandleCount: <unknown>\n");
    }
    else {
        printf("  HandleCount: %u\n", object_basic_info->HandleCount);
    }
#endif

    /* Query the object type. */
    PUBLIC_OBJECT_TYPE_INFORMATION* object_type_info = (PUBLIC_OBJECT_TYPE_INFORMATION*)buffer;
    bytes_needed = 0;
    status = NtQueryObject(target_handle, ObjectTypeInformation, object_type_info, buffer_size, &bytes_needed);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        printf("  Length needed to get TypeName: %d\n", bytes_needed);
    }
    if (NT_ERROR(status)) {
        printf("  TypeName: <unknown>\n");
    } else {
        printf("  TypeName: %ls\n", object_type_info->TypeName.Buffer);

        if (wcscmp(object_type_info->TypeName.Buffer, L"File") == 0) {
            // Get name of file from file handle.
            FILE_NAME_INFO* fni = (FILE_NAME_INFO*)buffer;
            if (!GetFileInformationByHandleEx(target_handle, FileNameInfo, fni, buffer_size)) {
                ULONG error = GetLastError();
                printf("  Name: <HResult %x>\n", HRESULT_FROM_WIN32(error));
            }
            else {
                WCHAR path[MAX_PATH];
                memcpy(path, fni->FileName, fni->FileNameLength);
                path[fni->FileNameLength / sizeof(WCHAR)] = 0;
                printf("  Name: %ls\n", path);
            }
        }
    }

    printf("\n");
    CloseHandle(target_handle);
}

void PrintSystemHandles(void)
{
    size_t shsize = sizeof(SYSTEM_HANDLE);
    ULONG bytes_needed = 0;
    ULONG handle_information_size = 32;
    SYSTEM_HANDLE_INFORMATION* handle_information = (SYSTEM_HANDLE_INFORMATION*)malloc(handle_information_size);
    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, handle_information, handle_information_size, &bytes_needed);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        free(handle_information);
        handle_information_size = bytes_needed;
        handle_information = (SYSTEM_HANDLE_INFORMATION*)malloc(handle_information_size);
        if (handle_information == nullptr) {
            printf("Out of memory\n");
            return;
        }
        status = NtQuerySystemInformation(SystemHandleInformation, handle_information, handle_information_size, &bytes_needed);
        if (NT_SUCCESS(status)) {
            for (ULONG i = 0; i < handle_information->Count; i++) {
                SYSTEM_HANDLE* system_handle = &handle_information->Handles[i];
#if 1 // DEBUG
                if (system_handle->ProcessId != 4432) {
                    continue;
                }
#endif
                HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE |
                    PROCESS_VM_READ,
                    FALSE, system_handle->ProcessId);
                if (process_handle == nullptr) {
                    continue;
                }

                HANDLE other_handle = (HANDLE)system_handle->Handle;
#if 0
                HANDLE target_handle;
                if (!DuplicateHandle(
                    process_handle,
                    other_handle,
                    GetCurrentProcess(),
                    &target_handle,
                    0,
                    FALSE,
                    DUPLICATE_SAME_ACCESS)) {
                    printf("DuplicateHandle failed with error %d\n", GetLastError());
                    CloseHandle(process_handle);
                    continue;
                }
#endif

                printf("PID %u: handle %p\n", system_handle->ProcessId, other_handle);
                printf("  type: %d\n", system_handle->ObjectTypeNumber);

                PrintHandleInfo(process_handle, other_handle);


                /* Query eBPF for its type info. */
                // We could use the QUERY_PROGRAM_INFO ioctl to get this. Or we could move this logic into kernel mode
                // and avoid all the user-kernel transitions, which seems better.

                CloseHandle(process_handle);
            }
        }
        free(handle_information);
    }
}

void PrintProcessHandles(HANDLE process_handle)
{
    DWORD handle_count;
    if (!GetProcessHandleCount(process_handle, &handle_count)) {
        return;
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
    PSS_CAPTURE_FLAGS capture_flags = PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION;
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
            PrintHandleInfo(process_handle, handle_entry.Handle);
        }

        PssWalkMarkerFree(walk_marker_handle);
    }
    PssFreeSnapshot(process_handle, snapshot_handle);
}

void PrintProcessNameAndID(DWORD process_id)
{
    TCHAR process_name[MAX_PATH] = TEXT("<unknown>");

    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);

    if (process_handle == nullptr) {
        return;
    }

    (void)GetModuleBaseName(process_handle, nullptr, process_name, sizeof(process_name) / sizeof(*process_name));
    _tprintf(TEXT("%s  (PID: %u)\n"), process_name, process_id);

    PrintProcessHandles(process_handle);

    CloseHandle(process_handle);
}

int main(int argc, char **argv)
{
    ULONG process_id = 0;
    if (argc > 1) {
        process_id = atoi(argv[1]);
        PrintProcessNameAndID(process_id);
        return 0;
    }
    //PrintSystemHandles();

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
