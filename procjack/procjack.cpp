/*
Abiks on SysInternalSuite (https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), eriti ProcExp, ProcMon ja VMMap.

Palju aega kulus materjalide läbilugemisele ning Windowsi protsessihalduse meeldetuletusele.

TODO:
1. dünaamiliselt notepad salvestatud/salvestamata andmete mälust leidmine (abiks WinDbg)
2. käsurealt protsessi nimi või PID anda kaasa
3. kontrollida, et mälu on loetav, vajadusel muuta mälukaitseid (abiks VMMap või Win32 APId)

*/

// hunnik artikleid ja muid viiteid
// windows desktop apps: https://learn.microsoft.com/en-us/cpp/windows/walkthrough-creating-windows-desktop-applications-cpp?view=msvc-170
// calculator example: https://learn.microsoft.com/en-us/cpp/get-started/tutorial-console-cpp?view=msvc-170
// using NTAPI: https://malwaretips.com/threads/theory-native-windows-api-ntapi.63573/
// legacy ANSI encoding: https://en.wikipedia.org/wiki/Windows-1252
// _tmain: https://learn.microsoft.com/en-us/cpp/cpp/main-function-command-line-args?view=msvc-170
// createprocess: https://learn.microsoft.com/en-us/windows/win32/procthread/creating-processes
// extracting unsaved memory: https://infosecwriteups.com/extracting-an-unsaved-memory-content-by-walking-through-windows-heaps-but-how-6992589d872e
// windbg: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg

#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <processthreadsapi.h>
#include <memoryapi.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>

//  Forward declarations:
BOOL GetProcessList();

using namespace std;

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

    /* TODO: print PID for debug purposes*/
    printf("Started %s with PID\n", "notepad.exe");
}

/*int GetProcessId(char* ProcName) {
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
        _tprintf(TEXT("\n  Parent process ID = 0x%08X"), pe32.th32ParentProcessID);
        _tprintf(TEXT("\n  Priority base     = %d"), pe32.pcPriClassBase);
        if (dwPriorityClass)
            _tprintf(TEXT("\n  Priority class    = %d"), dwPriorityClass);
        _tprintf(TEXT("\n====================================================="));

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return(pe32.th32ProcessID);
}

// https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-heap-list
int readHeaps(DWORD pid)
{
    HEAPLIST32 hl;

    HANDLE hHeapSnap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid);

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

            if (Heap32First(&he, pid, hl.th32HeapID))
            {
                printf("\nHeap ID: %d\n", hl.th32HeapID);
                do
                {
                    //printf("Block size: %d\n", he.dwBlockSize);
                    he.dwSize = sizeof(HEAPENTRY32);
                    //printf("Heap addr: 0x%08X\n", he.dwAddress);
                } while (Heap32Next(&he));
            }
            hl.dwSize = sizeof(HEAPLIST32);
        } while (Heap32ListNext(hHeapSnap, &hl));
    }
    else printf("Cannot list first heap (%d)\n", GetLastError());

    CloseHandle(hHeapSnap);

    return 0;
}

void _tmain(int argc, TCHAR* argv[])
{
    /* TODO: cmdline nargument for proc name */
    DWORD pid = GetProcessId();
    HANDLE handle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid
    );

    readHeaps(pid);

    if (!handle)
    {
        cout << "Failed to open handle to notepad.exe" << endl;
        return;
    }
    cout << "\n[+] Successfully opened handle to notepad.exe" << endl << endl;

    /* TODO: check if permissions are enabled for memory reading */

    // VMMap -> notepad.exe -> Heap -> Address
    LPCVOID targetAddress = (LPCVOID)0x0000025665a328bc;
    SIZE_T bytesRead;
    char buffer[32];

    // ref: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory
    if (!ReadProcessMemory(handle, targetAddress, buffer, sizeof(buffer), &bytesRead))
    {
        cerr << "Failed to read memory. Error: " << GetLastError() << endl;
        return;
    }

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
    cout << endl;

    /*
    PROCESSINFOCLASS pic;
    PROCESS_BASIC_INFORMATION pbi;
    PULONG retLen;

    // Zw for kernel-space, Nt for user-space, ref: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines
    NtQueryInformationProcess(
        pi.hProcess,
        pic,
        &pbi,
        sizeof(pbi),
        retLen
    );
    */


    // Wait until child process exits.
    // WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles. 
    CloseHandle(handle);
    // CloseHandle(pi.hThread);
}