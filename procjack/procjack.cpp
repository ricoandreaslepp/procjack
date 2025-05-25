/*
    Header
*/
#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <processthreadsapi.h>
#include <memoryapi.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>

using namespace std;

/* TODO: currently not used, but could be... 
    ref: https://learn.microsoft.com/en-us/windows/win32/procthread/creating-processes
*/
void startProcess()
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // start the child process
    if (!CreateProcess(NULL,   // No module name (use command line)
        (LPWSTR)"notepad.exe",        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi)           // Pointer to PROCESS_INFORMATION structure
        )
    {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return;
    }

    printf("Started %s with PID\n", "notepad.exe");

    // Wait until child process exits.
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

/* TODO: this looks much more efficient

int GetProcessId(char* ProcName) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = NULL;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (strcmp((const char *)pe32.szExeFile, ProcName) == 0)
                break;
        } while (Process32Next(hSnapshot, &pe32));
    }

    if (hSnapshot != INVALID_HANDLE_VALUE)
        CloseHandle(hSnapshot);

    return pe32.th32ProcessID;
}*/

// taken from and modified: https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
DWORD GetProcessId()
{
    BOOL found = false;
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32 pe32;
    DWORD dwPriorityClass;
    const TCHAR* locateProcessName = _T("notepad.exe"); /* TODO: make cmdline argument */

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        return(FALSE);
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return(FALSE);
    }

    // Now walk the snapshot of processes, and
    // display information about each process in turn
    do
    {

        if (_tcsicmp(pe32.szExeFile, locateProcessName) != 0)
            continue;

        _tprintf(TEXT("[+] Located the requested process"));
        _tprintf(TEXT("\n====================================================="));
        _tprintf(TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile);
        _tprintf(TEXT("\n-----------------------------------------------------"));

        // Retrieve the priority class.
        dwPriorityClass = 0;
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);

        if (hProcess == NULL)
        {
            DWORD error = GetLastError();
            _tprintf(TEXT("\nWARNING: OpenProcess failed for PID %d with error %lu"), pe32.th32ProcessID, error);
        }
        else
        {
            dwPriorityClass = GetPriorityClass(hProcess);
            CloseHandle(hProcess);
        }

        // 0x%08X
        _tprintf(TEXT("\n  Process ID        = %d"), pe32.th32ProcessID);
        _tprintf(TEXT("\n  Thread count      = %d"), pe32.cntThreads);
        _tprintf(TEXT("\n  Parent process ID = %d"), pe32.th32ParentProcessID);
        _tprintf(TEXT("\n  Priority base     = %d"), pe32.pcPriClassBase);
        if (dwPriorityClass)
            _tprintf(TEXT("\n  Priority class    = %d"), dwPriorityClass);
        _tprintf(TEXT("\n====================================================="));
        found = true;

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    if (!found) return(FALSE);
    return(pe32.th32ProcessID);
}

void ReadMemory(HANDLE hProcess, LPCVOID targetAddress, SIZE_T size) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T queryResult = VirtualQueryEx(hProcess, targetAddress, &mbi, sizeof(mbi));
    if (queryResult == 0) {
        cerr << "VirtualQueryEx failed. Error: " << GetLastError() << "\n";
        return;
    }

    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
        cerr << "Memory is not readable. Protection: " << mbi.Protect << "\n";
        return;
    }

    /*
    cout << "[+] Read " << bytesRead << " bytes from address 0x" << targetAddress << ": " << endl;
    for (SIZE_T i = 0; i < bytesRead; ++i) {
        cout << hex << (u_int)buffer[i] << " ";
    }
    cout << endl;

    cout << "[!] Unsaved text in ASCII:" << endl;
    for (SIZE_T i = 0; i < bytesRead; ++i) {
        if (buffer[i] != '0')
        {
            cout << buffer[i];
        }
    }
    cout << endl;*/

    BYTE buffer[4096];
    SIZE_T bytesRead;

    // ref: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory
    if (ReadProcessMemory(hProcess, targetAddress, buffer, sizeof(buffer), &bytesRead)) {
        cout << "Read " << bytesRead << " bytes from address: " << targetAddress << "\n";
        cout << "  Data: ";
        for (SIZE_T i = 0; i < bytesRead; ++i) {
            //if (buffer[i] != 0x6c || buffer[i] != 0x73) continue;
            if (buffer[i] < 32 || buffer[i] > 126) continue;
            cout << (char)buffer[i];

        }
        cout << "\n";
    } else {
        /* TODO: convert to FormatMessage
            ref: https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
        */
        cerr << "Failed to read memory. Error: " << GetLastError() << endl;
    }
}

/*
// https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-heap-list
// this only works for our current process :/, related: https://stackoverflow.com/questions/18901550/how-can-i-get-heap-info-from-another-process-in-c
int readHeaps(DWORD pid)
{
    HEAPLIST32 hl;
    HANDLE hHeapSnap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, GetCurrentProcessId());
    hl.dwSize = sizeof(HEAPLIST32);

    if (hHeapSnap == INVALID_HANDLE_VALUE)
    {
        printf("CreateToolhelp32Snapshot failed (%d)\n", GetLastError());
        return 1;
    }

    if (Heap32ListFirst(hHeapSnap, &hl))
    {
        do
        {
            HEAPENTRY32 he;
            ZeroMemory(&he, sizeof(HEAPENTRY32));
            he.dwSize = sizeof(HEAPENTRY32);

            if (Heap32First(&he, GetCurrentProcessId(), hl.th32HeapID))
            {
                cout << "\nHeap ID: " << hl.th32HeapID << endl;
                do
                {
                    //printf("Block size: %d\n", he.dwBlockSize);

                    he.dwSize = sizeof(HEAPENTRY32);
                } while (Heap32Next(&he));
            }
            hl.dwSize = sizeof(HEAPLIST32);
        } while (Heap32ListNext(hHeapSnap, &hl));
    }
    else printf("Cannot list first heap (%d)\n", GetLastError());

    CloseHandle(hHeapSnap);
}*/

void EnumerateMemoryRegions(HANDLE hProcess) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    LPCVOID address = sysInfo.lpMinimumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    while (address < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            cout << "Base Address: " << mbi.BaseAddress
                << ", Region Size: " << mbi.RegionSize
                << ", State: " << mbi.State
                << ", Protect: " << mbi.Protect << "\n";

            if (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
                cout << "  Readable region found.\n";
                ReadMemory(hProcess, address, mbi.RegionSize);
            }
            else if (mbi.Protect == PAGE_NOACCESS) {
                cout << "  Skipping PAGE_NOACCESS region.\n";
            }

            address = (LPCVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
        } else {
            cerr << "VirtualQueryEx failed at address: " << address << ". Error: " << GetLastError() << "\n";
            break;
        }
    }
}

void _tmain(int argc, TCHAR* argv[])
{
    /* TODO: cmdline nargument for proc name */
    DWORD pid = GetProcessId();
    if (!pid)
    {
        cerr << "[-] Could not locate the notepad.exe process" << endl;
        return;
    }

    /* The handle must have PROCESS_VM_READ access to the process */
    HANDLE handle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!handle)
    {
        cerr << "[-] Failed to open handle to notepad.exe" << endl;
        return;
    }
    cout << "\n[+] Successfully opened handle to notepad.exe" << endl << endl;

    EnumerateMemoryRegions(handle);

    LPCVOID targetAddr = (LPCVOID)0x01c6d23c;
    ReadMemory(handle, targetAddr, 1024);

    // VMMap -> notepad.exe -> Heap -> Address
    CloseHandle(handle);
    return;
}