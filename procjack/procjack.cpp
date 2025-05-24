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
using namespace std;

/* vb läheb mingi hetk kasutusse */
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

void _tmain(int argc, TCHAR* argv[])
{
    HANDLE handle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        /* TODO: resolve pid dynamically */
        36264 // notepad.exe PID
    );

    if (!handle)
    {
        cout << "Failed to open handle to notepad.exe" << endl;
        return;
    }
    cout << "[+] Successfully opened handle to notepad.exe" << endl << endl;

    /* TODO: check if permissions are enabled for memory reading */

    // VMMap -> notepad.exe -> Heap -> Address
    // LPCVOID targetAddress = (LPCVOID)0x25658530000;
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

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
