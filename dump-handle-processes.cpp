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

// Not on MSDN but listed at http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FType%20independed%2FOBJECT_NAME_INFORMATION.html
#define ObjectNameInformation ((OBJECT_INFORMATION_CLASS)1)
typedef struct {
    UNICODE_STRING          Name;
    WCHAR                   NameBuffer[1];
} OBJECT_NAME_INFORMATION;

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

void PrintLocalHandleInfo(DWORD process_id, HANDLE target_handle, const WCHAR* name, BYTE type, const WCHAR* type_name)
{
    DWORD file_type = GetFileType(target_handle);
    char buffer[80];
    PCSTR type_string;
    if (file_type == FILE_TYPE_CHAR) {
        type_string = "Char";
    } else if (file_type == FILE_TYPE_DISK) {
        type_string = "Disk";
    } else if (file_type == FILE_TYPE_PIPE) {
        type_string = "Pipe";
    } else {
        sprintf_s(buffer, sizeof(buffer), "%d", file_type);
        type_string = buffer;
    }
    printf("PID %d: FileType %-4s  Type %2d  TypeName %ls  ObjectName: %ls\n", process_id, type_string, type, type_name, name);
}

typedef struct {
    PCWSTR name_filter;
    HANDLE process_handle;
    HANDLE target_handle;
    PCWSTR type_name;
    BYTE type;
} query_name_param_t;

DWORD WINAPI QueryNameThreadProc(_In_ PVOID parameter)
{
    query_name_param_t* param = (query_name_param_t*)parameter;
    char buffer[1024];
    ULONG buffer_size = sizeof(buffer);
    NTSTATUS status;
    OBJECT_NAME_INFORMATION* object_name_info = (OBJECT_NAME_INFORMATION*)buffer;
    status = NtQueryObject(param->target_handle, ObjectNameInformation, object_name_info, buffer_size, nullptr);
    if (NT_SUCCESS(status) && (object_name_info->Name.Length > 0)) {
        if (!param->name_filter || wcsstr(object_name_info->NameBuffer, param->name_filter) != nullptr) {
            WCHAR name[1024];
            memcpy(name, object_name_info->Name.Buffer, object_name_info->Name.Length);
            name[object_name_info->Name.Length / sizeof(WCHAR)] = 0;
            PrintLocalHandleInfo(GetProcessId(param->process_handle), param->target_handle, object_name_info->NameBuffer, param->type, param->type_name);
        }
    }
    return 0;
}

// Print info on handle if we can get the name of the object it references.
void PrintHandleInfo(HANDLE process_handle, HANDLE other_handle, BYTE type, _In_opt_ PCWSTR name_filter)
{
    HANDLE target_handle;
    if (!DuplicateHandle(process_handle, other_handle, GetCurrentProcess(),
        &target_handle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        ULONG error = GetLastError();
        if (error == ERROR_NOT_SUPPORTED) {
            // Some handle types cannot be duplicated. This is ok, since the handles
            // we're looking for can be duplicated.
            return;
        }
        if (error == ERROR_ACCESS_DENIED) {
            // We can't duplicate handles in some system security processes. This is ok,
            // we just can't detect whether they have handles open of the type we're looking for.
            return;

        }
        if (error == ERROR_INVALID_HANDLE) {
            // Handle is already invalidated.
            return;
        }
        printf("PID %u DuplicateHandle failed with error %d\n", GetProcessId(process_handle), error);
        return;
    }

    char buffer[1024];
    ULONG buffer_size = sizeof(buffer);
    NTSTATUS status;
    PUBLIC_OBJECT_TYPE_INFORMATION object_type_info;
    ULONG bytes_needed = 0;
    status = NtQueryObject(target_handle, ObjectTypeInformation, buffer, buffer_size, &bytes_needed);
    if (!NT_SUCCESS(status)) {
        CloseHandle(target_handle);
        return;
    }
    memcpy(&object_type_info, buffer, sizeof(object_type_info));

    // Set a 200ms timeout for querying object name after which we just give up.
    query_name_param_t param;
    param.name_filter = name_filter;
    param.process_handle = process_handle;
    param.target_handle = target_handle;
    param.type = type;
    param.type_name = object_type_info.TypeName.Buffer;
    HANDLE thread = CreateThread(nullptr, 0, QueryNameThreadProc, &param, 0, nullptr);
    if (WaitForSingleObject(thread, 200) == WAIT_TIMEOUT) {
        TerminateThread(thread, 1);
    }
    CloseHandle(thread);

    CloseHandle(target_handle);
}

int PrintSystemHandles(_In_opt_ PCWSTR name)
{
    size_t shsize = sizeof(SYSTEM_HANDLE);
    ULONG bytes_needed = 0;
    ULONG handle_information_size = 32;
    SYSTEM_HANDLE_INFORMATION* handle_information;
    NTSTATUS status;

    for (int iterations = 0; iterations < 64; iterations++) {
        handle_information = (SYSTEM_HANDLE_INFORMATION*)malloc(handle_information_size);
        if (handle_information == nullptr) {
            printf("Out of memory\n");
            return 1;
        }
        status = NtQuerySystemInformation(SystemHandleInformation, handle_information, handle_information_size, &bytes_needed);
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            break;
        }
        free(handle_information);
        handle_information_size = max(bytes_needed, handle_information_size * 2);
    }
    if (NT_ERROR(status)) {
        printf("Error %x from NtQuerySystemInformation\n", status);
    } else {
        for (ULONG i = 0; i < handle_information->Count; i++) {
            SYSTEM_HANDLE* system_handle = &handle_information->Handles[i];

            HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, system_handle->ProcessId);
            if (process_handle == nullptr) {
                continue;
            }

            HANDLE other_handle = (HANDLE)system_handle->Handle;

            PrintHandleInfo(process_handle, other_handle, system_handle->ObjectTypeNumber, name);

            /* Query eBPF for its type info. */
            // We could use the QUERY_PROGRAM_INFO ioctl to get this. Or we could move this logic into kernel mode
            // and avoid all the user-kernel transitions, which seems better.

            CloseHandle(process_handle);
        }
    }

    free(handle_information);
    return 0;
}

void PrintProcessHandles(HANDLE process_handle, _In_opt_ PCWSTR name_filter)
{
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
            PrintHandleInfo(process_handle, handle_entry.Handle, handle_entry.ObjectType, name_filter);
        }

        PssWalkMarkerFree(walk_marker_handle);
    }
    PssFreeSnapshot(process_handle, snapshot_handle);
}

int PrintProcessNameAndID(DWORD process_id)
{
    WCHAR process_name[MAX_PATH] = L"<unknown>";

    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (process_handle == nullptr) {
        printf("Couldn't open process %u\n", process_id);
        return 1;
    }

    (void)GetModuleBaseName(process_handle, nullptr, process_name, sizeof(process_name) / sizeof(*process_name));
    printf("PID %u: %ls\n", process_id, process_name);

    PrintProcessHandles(process_handle, nullptr);

    CloseHandle(process_handle);
    return 0;
}

// TODO: delete these
void TestDeviceHandle(void)
{
#define EBPF_DEVICE_WIN32_NAME L"\\\\.\\EbpfIoDevice"
    HANDLE hFile = CreateFile(
            EBPF_DEVICE_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, 0);
    if (hFile) {
        PrintLocalHandleInfo(GetCurrentProcessId(), hFile, EBPF_DEVICE_WIN32_NAME, 0, L"test");
        CloseHandle(hFile);
    }
}

void TestFileHandle(void)
{
    const WCHAR* filename = L"c:\\temp\\deleteme.txt";
    HANDLE hFile = CreateFileW(filename, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (hFile) {
        PrintLocalHandleInfo(GetCurrentProcessId(), hFile, filename, 0, L"test");
        CloseHandle(hFile);
    }
}

int RunTests(void)
{
    TestFileHandle();
    TestDeviceHandle();
    return 0;
}

int PrintAllProcessInfo(void)
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

void PrintHelp(void)
{
    printf("Usage: dump-handle-processes <option>\n");
    printf("Options:\n");
    printf("  -t         Run tests\n");
    printf("  -a         Print all process info\n");
    printf("  -l         Print info for current process\n");
    printf("  -h <name>  Print info for all handles on a given name\n");
    printf("  -p <pid>   Print info for specified process ID\n");
}

int wmain(int argc, WCHAR **argv)
{
    ULONG process_id = 0;
    if (argc > 1) {
        if (wcscmp(argv[1], L"-t") == 0) {
            return RunTests();
        }
        if (wcscmp(argv[1], L"-a") == 0) {
            return PrintAllProcessInfo();
        }
        if (wcscmp(argv[1], L"-l") == 0) {
            process_id = GetCurrentProcessId();
            return PrintProcessNameAndID(process_id);
        }
        if (argc > 2 && wcscmp(argv[1], L"-p") == 0) {
            process_id = _wtoi(argv[2]);
            return PrintProcessNameAndID(process_id);
        }
        if (wcscmp(argv[1], L"-s") == 0) {
            return PrintSystemHandles(nullptr);
        }
        if (argc > 2 && wcscmp(argv[1], L"-h") == 0) {
            return PrintSystemHandles(argv[2]);
        }
    }
    PrintHelp();
    return 0;
}
