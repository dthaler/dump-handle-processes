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

typedef enum : BYTE {
    Directory = 3,
    TypeUnknown4 = 4, // Can't get type info.
    Token = 5,
    Job = 6,
    Process = 7,
    Thread = 8,
    TypeUnknown9 = 9, // Can't get type info.
    UserApcReserve = 10,
    IoCompletionReserve = 11,
    Event = 16,
    Mutant = 17,
    Semaphore = 19,
    Timer = 20,
    IRTimer = 21,
    WindowStation = 24,
    Desktop = 25,
    Composition = 26,
    RawInputManager = 27,
    TypeUnknown28 = 28, // Can't get type info.
    TpWorkerFactory = 30,
    IoCompletion = 35,
    WaitCompletionPacket = 36,
    File = 37,
    TypeUnknown38 = 38, // Can't get type info.
    TypeUnknown40 = 40, // Can't get type info.
    Section = 42,
    TypeUnknown43 = 43, // Can't get type info.
    Key = 44,
    ALPCPort = 46,
    EnergyTracker = 47,
    TypeUnknown48 = 48, // Can't get type info.
    WmiGuid = 49,
    TypeUnknown50 = 50, // Can't get type info.
    TypeUnknown52 = 52, // Can't get type info.
    TypeUnknown55 = 55, // Can't get type info.
    TypeUnknown56 = 56, // Can't get type info.
    TypeUnknown57 = 57, // Can't get type info.
    DxgkSharedResource = 59,
    DxgkSharedSyncObject = 61,
    DxgkDisplayManagerObject = 63,
    DxgkCompositionObject = 67
} object_type_number_t;

#define SystemHandleInformation ((SYSTEM_INFORMATION_CLASS)16)
typedef struct
{
    ULONG ProcessId;
    object_type_number_t ObjectTypeNumber;
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

void PrintLocalHandleInfo(HANDLE process_handle, HANDLE target_handle, const WCHAR* name, BYTE type, const WCHAR* type_name, DWORD file_type)
{
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

    WCHAR process_name[MAX_PATH];
    (void)GetModuleBaseName(process_handle, nullptr, process_name, sizeof(process_name) / sizeof(*process_name));
    DWORD process_id = GetProcessId(process_handle);

    /* Query eBPF for its type info. */
    // We could use the QUERY_PROGRAM_INFO ioctl to get this. Or we could move this logic into kernel mode
    // and avoid all the user-kernel transitions.

    printf("PID %d (%ls): FileType %-4s  Type %2d  TypeName %ls  ObjectName: %ls\n", process_id, process_name, type_string, type, type_name, name);
}

typedef struct {
    HANDLE target_handle;
    DWORD file_type;
    WCHAR name[1024];
} query_name_param_t;

DWORD WINAPI QueryNameThreadProc(_In_ PVOID parameter)
{
    query_name_param_t* param = (query_name_param_t*)parameter;

    param->file_type = GetFileType(param->target_handle);
#if 0
    printf("DEBUG %p: ft %d \n", param->target_handle, param->file_type);
    fflush(stdout);
#endif

    char buffer[1024];
    ULONG buffer_size = sizeof(buffer);
    NTSTATUS status;
    OBJECT_NAME_INFORMATION* object_name_info = (OBJECT_NAME_INFORMATION*)buffer;
    status = NtQueryObject(param->target_handle, ObjectNameInformation, object_name_info, buffer_size, nullptr);
    if (NT_SUCCESS(status) && (object_name_info->Name.Length > 0)) {
        memcpy(param->name, object_name_info->Name.Buffer, object_name_info->Name.Length);
        param->name[object_name_info->Name.Length / sizeof(WCHAR)] = 0;
    } else {
        param->name[0] = 0;
    }
    return 0;
}

PCWSTR types_to_skip[] = {
    L"ALPC Port",
    L"Composition",
    L"DebugObject",
    L"Desktop", // has object name
    L"Directory", // has object name
    L"DxgkCompositionObject",
    L"DxgkDisplayManagerObject",
    L"DxgkSharedResource",
    L"DxgkSharedSyncObject",
    L"EnergyTracker",
    L"Event",
    L"IoCompletion",
    L"IoCompletionReserve",
    L"IRTimer",
    L"Job",
    L"Key", // has object name (registry key)
    L"Mutant", // has object name
    L"Partition", // has object name
    L"Process",
    L"RawInputManager",
    L"Section",
    L"Semaphore", // has object name
    L"Session", // has object name
    L"Thread",
    L"Timer",
    L"Token",
    L"TpWorkerFactory",
    L"UserApcReserve",
    L"WaitCompletionPacket",
    L"WindowStation", // has object name
    L"WmiGuid",
};

PCWSTR types_to_include[] = {
    L"File",
};

bool SkipType(PCWSTR type_name)
{
    for (int i = 0; i < sizeof(types_to_include) / sizeof(*types_to_include); i++) {
        if (wcscmp(type_name, types_to_include[i]) == 0) {
            return false;
        }
    }

    // Skip various types explicitly.
    for (int i = 0; i < sizeof(types_to_skip) / sizeof(*types_to_skip); i++) {
        if (wcscmp(type_name, types_to_skip[i]) == 0) {
            return true;
        }
    }

    return false;
}

// Print info on handle if we can get the name of the object it references.
void PrintHandleInfo(HANDLE process_handle, HANDLE other_handle, BYTE type, _In_opt_ PCWSTR name_filter, int file_type_filter)
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

    if ((file_type_filter != -1) && (GetFileType(target_handle) != file_type_filter)) {
        // Not the type we're looking for.
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

    if (SkipType(object_type_info.TypeName.Buffer)) {
        CloseHandle(target_handle);
        return;
    }

    // Set a 200ms timeout for querying object name after which we just give up.
    query_name_param_t param = {};
    param.target_handle = target_handle;
    // TODO: for perf, reuse a thread instead of creating a new one per handle.
    HANDLE thread = CreateThread(nullptr, 0, QueryNameThreadProc, &param, 0, nullptr);
    if (WaitForSingleObject(thread, 200) == WAIT_TIMEOUT) {
        TerminateThread(thread, 1);
    }
    CloseHandle(thread);
    if (!name_filter || wcsstr(param.name, name_filter) != nullptr) {
        PrintLocalHandleInfo(process_handle, target_handle, param.name, type, object_type_info.TypeName.Buffer, param.file_type);
    }

    CloseHandle(target_handle);
}

int PrintSystemHandles(_In_opt_ PCWSTR name_filter, int file_type_filter)
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
        DWORD current_process_id = 0;
        HANDLE current_process_handle = nullptr;
        for (ULONG i = 0; i < handle_information->Count; i++) {
            SYSTEM_HANDLE* system_handle = &handle_information->Handles[i];

            switch (system_handle->ObjectTypeNumber) {
            // Ignore thread, semaphore, event, etc. handles.
            case ALPCPort:
            case Composition:
            case Desktop:
            case DxgkCompositionObject:
            case DxgkDisplayManagerObject:
            case DxgkSharedResource:
            case DxgkSharedSyncObject:
            case EnergyTracker:
            case Event:
            case IoCompletion:
            case IoCompletionReserve:
            case IRTimer:
            case Job:
            case Key: // has names
            case Mutant: // has names
            case Process:
            case RawInputManager:
            case Section: // has names
            case Semaphore:
            case Thread:
            case Timer:
            case Token:
            case TpWorkerFactory:
            case TypeUnknown28:
            case TypeUnknown38:
            case TypeUnknown4:
            case TypeUnknown40:
            case TypeUnknown43:
            case TypeUnknown48:
            case TypeUnknown50:
            case TypeUnknown52:
            case TypeUnknown55:
            case TypeUnknown56:
            case TypeUnknown57:
            case TypeUnknown9:
            case UserApcReserve:
            case WaitCompletionPacket:
            case WindowStation:
            case WmiGuid:
                continue;
            // Show file, directory, etc. handles.
            case Directory:
            case File:
                break;
            default:
                printf("What is %d?\n", system_handle->ObjectTypeNumber);
                break;
            }

            // Batch process opens.
            if (system_handle->ProcessId != current_process_id) {
                current_process_id = system_handle->ProcessId;
                if (current_process_handle) {
                    CloseHandle(current_process_handle);
                }
                current_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, system_handle->ProcessId);
            }
            if (current_process_handle == nullptr) {
                continue;
            }

            HANDLE other_handle = (HANDLE)system_handle->Handle;

            PrintHandleInfo(current_process_handle, other_handle, system_handle->ObjectTypeNumber, name_filter, file_type_filter);
        }
        if (current_process_handle) {
            CloseHandle(current_process_handle);
        }
    }

    free(handle_information);
    return 0;
}

void PrintProcessHandles(HANDLE process_handle, _In_opt_ PCWSTR name_filter, int file_type_filter)
{
    HPSS snapshot_handle = nullptr;
    PSS_CAPTURE_FLAGS capture_flags = PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION;
    DWORD result = PssCaptureSnapshot(process_handle, capture_flags, 0, &snapshot_handle);
    if (result != ERROR_SUCCESS) {
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

            if (handle_entry.ObjectType != 0) {
                // Ignore thread, semaphore, event, etc. handles.
                continue;
            }

            PrintHandleInfo(process_handle, handle_entry.Handle, 0, name_filter, file_type_filter);
        }

        PssWalkMarkerFree(walk_marker_handle);
    }
    PssFreeSnapshot(process_handle, snapshot_handle);
}

int PrintProcessNameAndID(DWORD process_id, _In_opt_ PCWSTR object_name_filter)
{
    WCHAR process_name[MAX_PATH] = L"<unknown>";

    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (process_handle == nullptr) {
        return 1;
    }

    PrintProcessHandles(process_handle, object_name_filter, -1);

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
        PrintLocalHandleInfo(GetCurrentProcess(), hFile, EBPF_DEVICE_WIN32_NAME, 0, L"test", GetFileType(hFile));
        CloseHandle(hFile);
    }
}

void TestFileHandle(void)
{
    const WCHAR* filename = L"c:\\temp\\deleteme.txt";
    HANDLE hFile = CreateFileW(filename, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (hFile) {
        PrintLocalHandleInfo(GetCurrentProcess(), hFile, filename, 0, L"test", GetFileType(hFile));
        CloseHandle(hFile);
    }
}

int RunTests(void)
{
    TestFileHandle();
    TestDeviceHandle();
    return 0;
}

int PrintAllProcessInfo(_In_opt_ PCWSTR object_name_filter)
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
            PrintProcessNameAndID(processes[i], object_name_filter);
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
    printf("  -e         Print all eBPF handles\n");
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
            return PrintAllProcessInfo(nullptr);
        }
        if (wcscmp(argv[1], L"-e") == 0) {
            return PrintSystemHandles(L"\\Device\\EbpfIoDevice", FILE_TYPE_CHAR);
        }
        if (wcscmp(argv[1], L"-f") == 0) {
            return PrintAllProcessInfo(L"\\Device\\EbpfIoDevice");
        }
        if (wcscmp(argv[1], L"-l") == 0) {
            process_id = GetCurrentProcessId();
            return PrintProcessNameAndID(process_id, nullptr);
        }
        if (argc > 2 && wcscmp(argv[1], L"-p") == 0) {
            process_id = _wtoi(argv[2]);
            return PrintProcessNameAndID(process_id, nullptr);
        }
        if (wcscmp(argv[1], L"-s") == 0) {
            return PrintSystemHandles(nullptr, -1);
        }
        if (argc > 2 && wcscmp(argv[1], L"-h") == 0) {
            return PrintSystemHandles(argv[2], -1);
        }
    }
    PrintHelp();
    return 0;
}
