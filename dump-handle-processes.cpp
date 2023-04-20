#include <windows.h>
#include <stdio.h>
#include <tchar.h>

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1
#pragma comment(lib, "Psapi.lib")
#define PSAPI_VERSION 1
#include <psapi.h>

void PrintProcessNameAndID(DWORD process_id)
{
    TCHAR process_name[MAX_PATH] = TEXT("<unknown>");

    HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, process_id);

    if (NULL != process_handle) {
        (void)GetModuleBaseName(process_handle, nullptr, process_name, sizeof(process_name) / sizeof(*process_name));
        _tprintf(TEXT("%s  (PID: %u)\n"), process_name, process_id);
    }

    // Release the handle to the process.
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

/* Take snapshot of each process.
   For each handle, query eBPF for its type info.
 */
}
