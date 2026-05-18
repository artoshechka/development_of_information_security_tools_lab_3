#include <Windows.h>
#include <stdio.h>

#define LOCAL_BLOCKDLLPOLICY
#define STOP_ARG "xakep"

BOOL CreateProcessWithBlockDllPolicy(IN LPSTR lpProcessPath, OUT DWORD* dwProcessId,
    OUT HANDLE* hProcess, OUT HANDLE* hThread)
{
    STARTUPINFOEXA SiEx = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    SIZE_T sAttrSize = NULL;

    if (lpProcessPath == NULL)
        return FALSE;

    RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    SiEx.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    InitializeProcThreadAttributeList(NULL, 1, NULL, &sAttrSize);

    LPPROC_THREAD_ATTRIBUTE_LIST pAttrBuf =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sAttrSize);

    if (!InitializeProcThreadAttributeList(pAttrBuf, 1, NULL, &sAttrSize)) {
        printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    if (!UpdateProcThreadAttribute(pAttrBuf, NULL,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwPolicy, sizeof(DWORD64), NULL, NULL)) {
        printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    SiEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)pAttrBuf;

    if (!CreateProcessA(
        NULL,
        lpProcessPath,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &SiEx.StartupInfo,
        &Pi)) {
        printf("[!] CreateProcessA Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    DeleteProcThreadAttributeList(pAttrBuf);
    HeapFree(GetProcessHeap(), 0, pAttrBuf);

    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;
    else
        return FALSE;
}

int main(int argc, char* argv[])
{
    DWORD dwProcessId = NULL;
    HANDLE hProcess = NULL, hThread = NULL;

#ifdef LOCAL_BLOCKDLLPOLICY
    if (argc == 2 && (strcmp(argv[1], STOP_ARG) == 0)) {
        Sleep(500);
        printf("[+] Process Is Now Protected With The Block Dll Policy\n");
        printf("PID: %lu\n", GetCurrentProcessId());

        int i = 0;
        while (TRUE) {
            printf("Processing - %d\n", i++);
            Sleep(1000);
        }
    }
    else {
        printf("[!] Local Process Is Not Protected With The Block Dll Policy\n");

        CHAR pcFilename[MAX_PATH * 2];
        if (!GetModuleFileNameA(NULL, (LPSTR)&pcFilename, MAX_PATH * 2)) {
            printf("[!] GetModuleFileNameA Failed With Error : %d \n", GetLastError());
            return -1;
        }

        DWORD dwBufferSize = (DWORD)(lstrlenA(pcFilename) + lstrlenA(STOP_ARG) + 0xFF);
        CHAR* pcBuffer = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);
        if (!pcBuffer)
            return -1;

        sprintf_s(pcBuffer, dwBufferSize, "%s %s", pcFilename, STOP_ARG);

        if (!CreateProcessWithBlockDllPolicy(pcBuffer, &dwProcessId, &hProcess, &hThread)) {
            HeapFree(GetProcessHeap(), 0, pcBuffer);
            return -1;
        }

        HeapFree(GetProcessHeap(), 0, pcBuffer);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        printf("[i] Protected Process Created With PID %d\n", dwProcessId);
        printf("[i] Press any key to close this window...\n");
        getchar();
    }
#endif

#ifndef LOCAL_BLOCKDLLPOLICY
    if (!CreateProcessWithBlockDllPolicy(
        (LPSTR)"C:\\Windows\\System32\\RuntimeBroker.exe",
        &dwProcessId, &hProcess, &hThread)) {
        return -1;
    }
    printf("[i] Process Created With Pid %d \n", dwProcessId);
#endif

    return 0;
}
