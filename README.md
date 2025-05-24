# procjack
Windows process memory shenanigans.

## Usage
Clone the repo and open the Solution (`.sln`) file in Visual Studio 2022.

```bash
git clone https://github.com/ricoandreaslepp/procjack.git
```

## TODO
- [ ] dünaamiliselt notepad salvestatud/salvestamata andmete mälust leidmine (abiks WinDbg)
- [ ] käsurealt protsessi nimi või PID anda kaasa
- [ ] kontrollida, et mälu on loetav, vajadusel muuta mälukaitseid (abiks VMMap või Win32 APId)

## Helpful references
* [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) - especially ProcExp, ProcMon, and VMMap
* windows desktop apps: https://learn.microsoft.com/en-us/cpp/windows/walkthrough-creating-windows-desktop-applications-cpp?view=msvc-170
* calculator example: https://learn.microsoft.com/en-us/cpp/get-started/tutorial-console-cpp?view=msvc-170
* using NTAPI: https://malwaretips.com/threads/theory-native-windows-api-ntapi.63573/
* legacy ANSI encoding: https://en.wikipedia.org/wiki/Windows-1252
* _tmain: https://learn.microsoft.com/en-us/cpp/cpp/main-function-command-line-args?view=msvc-170
* createprocess: https://learn.microsoft.com/en-us/windows/win32/procthread/creating-processes
* extracting unsaved memory: https://infosecwriteups.com/extracting-an-unsaved-memory-content-by-walking-through-windows-heaps-but-how-6992589d872e
* windbg: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg
