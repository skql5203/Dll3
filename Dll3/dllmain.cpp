#include "pch.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <winternl.h>
#include <tlhelp32.h>
#include <map>
#include <atomic>
#include <unordered_set>
#include <ctime>

static int g_SendMessageWCount = 0;
static int g_SendMessageACount = 0;
static int g_WriteFileCount = 0;
static int g_NtWriteFileCount = 0;
static int flag_1_count = 0;
static int flag1 = 0;
static int flag2 = 0;
static int flag3 = 0;
const char* de = "";

std::map<std::string, std::atomic<int>> moduleInvocationCount;
std::unordered_set<std::string> flaggedModules;

typedef LRESULT(WINAPI* SendMessageW_t)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
typedef LRESULT(WINAPI* SendMessageA_t)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
typedef NTSTATUS(WINAPI* NtWriteFile_t)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
    );
typedef BOOL(WINAPI* WriteFile_t)(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
    );

SendMessageW_t Real_SendMessageW = nullptr;
SendMessageA_t Real_SendMessageA = nullptr;
NtWriteFile_t Real_NtWriteFile = nullptr;



// 경로에서 파일 이름을 추출하는 함수
const char* GetFileName(const char* path)
{
    const char* fileName = strrchr(path, '\\');
    if (fileName)
        return fileName + 1;
    return path;
}

bool IsSpecificMsg(UINT Msg) {
    return Msg == 13 || Msg == 14 || Msg == 2006 || Msg == 2162 || Msg == 2183 || Msg == 2182;
}

LRESULT WINAPI Hooked_SendMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    g_SendMessageWCount++;
    if (IsSpecificMsg(Msg)) {
        flag_1_count++;
    }
    return Real_SendMessageW(hWnd, Msg, wParam, lParam);
}

LRESULT WINAPI Hooked_SendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    g_SendMessageACount++;
    if (IsSpecificMsg(Msg)) {
        flag_1_count++;
    }

    return Real_SendMessageA(hWnd, Msg, wParam, lParam);
}
static int onc = 0;
NTSTATUS WINAPI Hooked_NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
) {
    g_NtWriteFileCount++;
    std::string msg = "NtWriteFile called (" + std::to_string(g_NtWriteFileCount) + " times)\n";
    OutputDebugStringA(msg.c_str());

    if (flag1 == 1 && flag2 == 1) {
        if (onc == 0) {
            HANDLE hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, L"Keettoo1234");
            if (!hEvent) {
                std::cerr << "Failed to open event. Error: " << GetLastError() << std::endl;
                return 1;
            }
            if (!SetEvent(hEvent)) {
                std::cerr << "Failed to set event. Error: " << GetLastError() << std::endl;
                CloseHandle(hEvent);
                return 1;
            }
            CloseHandle(hEvent);
        }
        onc = 1;

        return Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, (PVOID)de, 1, ByteOffset, Key);
    }
    else if (flag3 == 1 && flag2 == 1) {
        // 호출 스택을 캡처
        PVOID stack[10];
        USHORT frames = RtlCaptureStackBackTrace(1, 10, stack, NULL);

        // 캡처한 스택에서 호출 주소
        for (USHORT i = 0; i < frames; i++) {
            DWORD returnAddress = (DWORD)stack[i];

            // DLL의 주소 범위인지, 실행 파일의 주소 범위인지 확인
            MEMORY_BASIC_INFORMATION mbi;
            VirtualQuery((LPCVOID)returnAddress, &mbi, sizeof(mbi));
            char modulePath[MAX_PATH];
            GetModuleFileNameA((HMODULE)mbi.AllocationBase, modulePath, MAX_PATH);
            const char* moduleName = GetFileName(modulePath);

            const char* whitelist[] = {
                "SHLWAPI.dll",
                "dbghelp.dll",
                "VERSION.dll",
                "CRYPT32.dll",
                "WINTRUST.dll",
                "SensApi.dll",
                "WININET.dll",
                "dwmapi.dll",
                "GDI32.dll",

                "ADVAPI32.dll",
                "ole32.dll",
                "OLEAUT32.dll",
                "ucrtbase.dll",
                "COMCTL32.dll",
                "MSCTF.dll",
                "notepad++.exe",
                "IMM32.dll",
                "UxTheme.dll",
                "COMDLG32.dll",
                "DUI70.dll",
                "SHELL32.dll",
                "KERNELBASE.dll",
                "ntdll.dll",
                "USER32.dll",
                "RPCRT4.dll"

            };

            bool isWhitelisted = false;
            for (const auto& name : whitelist)
            {
                if (_stricmp(moduleName, name) == 0)
                {
                    isWhitelisted = true;
                    break;
                }
            }

            if (!isWhitelisted)
            {
                if (flaggedModules.find(moduleName) != flaggedModules.end()) {

                    return Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, (PVOID)de, 1, ByteOffset, Key);
                }

                moduleInvocationCount[moduleName]++;
                std::string msg = "in notepad++, " + std::string(moduleName) + " WriteFile called (" + std::to_string(g_NtWriteFileCount) + " times)\n";
                OutputDebugStringA(msg.c_str());

                if (moduleInvocationCount[moduleName] >= 5) {

                    HANDLE hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, L"Keettoo1234");
                    if (!hEvent) {
                        std::cerr << "Failed to open event. Error: " << GetLastError() << std::endl;
                        return 1;
                    }
                    if (!SetEvent(hEvent)) {
                        std::cerr << "Failed to set event. Error: " << GetLastError() << std::endl;
                        CloseHandle(hEvent);
                        return 1;
                    }
                    CloseHandle(hEvent);

                    flaggedModules.insert(moduleName);
                    std::string attackMsg = "AATTAACCKK!!!! Module: " + std::string(moduleName) + "\n";
                    OutputDebugStringA(attackMsg.c_str());
                    return Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, (PVOID)de, 1, ByteOffset, Key);
                }
                else {
                    break;
                }
            }
        }
    }

    return Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

void HookIAT(HMODULE hModule, const char* importModuleName, const char* importFunctionName, void* hookedFunction, void** originalFunction) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDesc->Name) {
        const char* moduleName = (const char*)((BYTE*)hModule + pImportDesc->Name);
        if (_stricmp(moduleName, importModuleName) == 0) {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);
            PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->OriginalFirstThunk);
            while (pThunk->u1.Function) {
                PROC* ppfn = (PROC*)&pThunk->u1.Function;
                const char* functionName = (const char*)((BYTE*)hModule + pOriginalThunk->u1.AddressOfData + 2);
                if (_stricmp(functionName, importFunctionName) == 0) {
                    DWORD oldProtect;
                    VirtualProtect(ppfn, sizeof(PROC), PAGE_READWRITE, &oldProtect);
                    *originalFunction = (void*)*ppfn;
                    *ppfn = (PROC)hookedFunction;
                    VirtualProtect(ppfn, sizeof(PROC), oldProtect, &oldProtect);
                    break;
                }
                pThunk++;
                pOriginalThunk++;
            }
        }
        pImportDesc++;
    }
}

void HookAllModules(const char* importModuleName, const char* importFunctionName, void* hookedFunction, void** originalFunction) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnapshot, &me32)) {
        do {
            HookIAT(me32.hModule, importModuleName, importFunctionName, hookedFunction, originalFunction);
        } while (Module32Next(hSnapshot, &me32));
    }

    CloseHandle(hSnapshot);
}

DWORD WINAPI monitoring(LPVOID lpParameter) {
    while (true) {
        int initial_flag_1_count = flag_1_count;
        int initial_NtWriteFileCount = g_NtWriteFileCount;

        Sleep(10000);

        int d1 = flag_1_count - initial_flag_1_count;
        int d3 = g_NtWriteFileCount - initial_NtWriteFileCount;
        if (1) {


            if (d1 >= 6) {
                flag1 = 1;
            }
        }
        if (d3 >= 6) {
            flag2 = 1;
        }
        if (flag1 && flag2) {
            OutputDebugStringA("attack detected!!!!!");
        }

        for (auto& entry : moduleInvocationCount) {
            if (flaggedModules.find(entry.first) == flaggedModules.end()) {
                entry.second = 0;
            }
        }
    }
    return 0;
}

BOOL IsCurrentProcessNotepadPlusPlus()
{
    char processName[MAX_PATH] = { 0 };
    DWORD pid = GetCurrentProcessId();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return FALSE;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe))
    {
        do
        {
            if (pe.th32ProcessID == pid)
            {
                WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, processName, MAX_PATH, NULL, NULL);
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);

    return _stricmp(processName, "notepad++.exe") == 0;
}




void RestoreWriteFileIAT(HMODULE hModule) {
    bool writeFileIATModified = false;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDesc->Name) {
        const char* moduleName = (const char*)((BYTE*)hModule + pImportDesc->Name);
        if (_stricmp(moduleName, "kernel32.dll") == 0) {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);
            PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->OriginalFirstThunk);
            while (pThunk->u1.Function) {
                PROC* ppfn = (PROC*)&pThunk->u1.Function;
                const char* functionName = (const char*)((BYTE*)hModule + pOriginalThunk->u1.AddressOfData + 2);
                if (_stricmp(functionName, "WriteFile") == 0) {
                    DWORD oldProtect;
                    VirtualProtect(ppfn, sizeof(PROC), PAGE_READWRITE, &oldProtect);
                    if (*ppfn != (PROC)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "WriteFile")) {
                        writeFileIATModified = true;
                    }
                    *ppfn = (PROC)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "WriteFile");
                    VirtualProtect(ppfn, sizeof(PROC), oldProtect, &oldProtect);
                    break;
                }
                pThunk++;
                pOriginalThunk++;
            }
        }
        pImportDesc++;
    }

    // WriteFile의 IAT가 변조되었다면 표시
    if (writeFileIATModified) {
        HANDLE hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, L"Keettoo1234");
        if (!hEvent) {
            std::cerr << "Failed to open event. Error: " << GetLastError() << std::endl;
            return;
        }
        if (!SetEvent(hEvent)) {
            std::cerr << "Failed to set event. Error: " << GetLastError() << std::endl;
            CloseHandle(hEvent);
            return;
        }
        CloseHandle(hEvent);
    }
}

DWORD WINAPI ThreadFunction(LPVOID lpParam) {
    int k = 1;
    while (k) {
        RestoreWriteFileIAT(GetModuleHandle(NULL));
        Sleep(20000); 
        RestoreWriteFileIAT(GetModuleHandle(NULL));
        k = 0;
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DWORD threadId;

        HANDLE hThread = CreateThread(
            NULL,
            0,
            ThreadFunction,
            NULL,
            0,
            &threadId);

        if (hThread == NULL) {
            std::cerr << "CreateThread failed, error: " << GetLastError() << std::endl;
            return 1;
        }
        OutputDebugStringA("inject success!\n");
        flag3 = IsCurrentProcessNotepadPlusPlus();
        if (flag3) {
            HMODULE ntdll = GetModuleHandleA("ntdll.dll");
            if (ntdll) {
                Real_NtWriteFile = (NtWriteFile_t)GetProcAddress(ntdll, "NtWriteFile");
                if (Real_NtWriteFile) {
                    HookAllModules("ntdll.dll", "NtWriteFile", (void*)Hooked_NtWriteFile, (void**)&Real_NtWriteFile);
                }
            }
            CreateThread(NULL, 0, monitoring, NULL, 0, NULL);
        }
        else {
            HMODULE mainModule = GetModuleHandle(NULL);
            if (mainModule) {
                HMODULE user32 = GetModuleHandleA("user32.dll");
                if (user32) {
                    Real_SendMessageW = (SendMessageW_t)GetProcAddress(user32, "SendMessageW");
                    if (Real_SendMessageW) {
                        HookIAT(mainModule, "user32.dll", "SendMessageW", (void*)Hooked_SendMessageW, (void**)&Real_SendMessageW);
                    }
                    Real_SendMessageA = (SendMessageA_t)GetProcAddress(user32, "SendMessageA");
                    if (Real_SendMessageA) {
                        HookIAT(mainModule, "user32.dll", "SendMessageA", (void*)Hooked_SendMessageA, (void**)&Real_SendMessageA);
                    }
                }

                HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                if (ntdll) {
                    Real_NtWriteFile = (NtWriteFile_t)GetProcAddress(ntdll, "NtWriteFile");
                    if (Real_NtWriteFile) {
                        HookAllModules("ntdll.dll", "NtWriteFile", (void*)Hooked_NtWriteFile, (void**)&Real_NtWriteFile);
                    }
                }
            }


            CreateThread(NULL, 0, monitoring, NULL, 0, NULL);
        }
    }
    return TRUE;
}
