#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <winerror.h>
#include <strsafe.h>

#include <winternl.h>
#pragma comment(lib, "ntdll.lib")
#include <ntstatus.h>

#pragma comment(lib, "psapi.lib")
#define PSAPI_VERSION 1
#include <psapi.h>
#include <processsnapshot.h>

#define SystemHandleInformation ((SYSTEM_INFORMATION_CLASS)16)

typedef struct {
    UNICODE_STRING          Name;
    WCHAR                   NameBuffer[1];
} OBJECT_NAME_INFORMATION;

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

void PrintLocalHandleInfo(HANDLE target_handle)
{
    char buffer[1024];
    ULONG buffer_size = sizeof(buffer);
    ULONG bytes_needed;
    NTSTATUS status;

    DWORD type = GetFileType(target_handle);
    if (type == FILE_TYPE_CHAR) {
        printf(" Device: ");
    } else if (type == FILE_TYPE_DISK) {
        printf(" File: ");
    } else {
        printf(" Other: ");
    }

#define ObjectNameInformation ((OBJECT_INFORMATION_CLASS)1)
    // Not on MSDN but listed at http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FType%20independed%2FOBJECT_NAME_INFORMATION.html
    OBJECT_NAME_INFORMATION* object_name_info = (OBJECT_NAME_INFORMATION*)buffer;
    bytes_needed = 0;
    status = NtQueryObject(target_handle, ObjectNameInformation, object_name_info, buffer_size, &bytes_needed);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        printf("  Length needed to get HandleCount: %d\n", bytes_needed);
    }
    if (NT_ERROR(status)) {
        printf("  ObjectName: <unknown>\n");
    } else {
        printf("  ObjectName: %ls\n", object_name_info->NameBuffer);
    }
    printf("\n");
}

void PrintHandleInfo(HANDLE process_handle, HANDLE other_handle)
{
    HANDLE target_handle;
    if (!DuplicateHandle(process_handle, other_handle, GetCurrentProcess(),
        &target_handle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        printf("DuplicateHandle failed with error %d\n", GetLastError());
        return;
    }

    PrintLocalHandleInfo(target_handle);
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

void TestDeviceHandle(void)
{
#define EBPF_DEVICE_WIN32_NAME L"\\\\.\\EbpfIoDevice"
    HANDLE hFile = CreateFile(
            EBPF_DEVICE_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, 0);

    PrintLocalHandleInfo(hFile);
    CloseHandle(hFile);
}

void TestFileHandle(void)
{
    HANDLE hFile = CreateFileW(L"c:\\temp\\deleteme.txt", GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);

    PrintLocalHandleInfo(hFile);

    CloseHandle(hFile);
}

int main(int argc, char **argv)
{
    //TestFileHandle();
    //TestDeviceHandle();

    ULONG process_id = 0;
    if (argc > 1) {
        process_id = atoi(argv[1]);
        if (!process_id) {
            process_id = GetCurrentProcessId();
        }
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
